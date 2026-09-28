/* HTTP and WebSocket plumbing for hushd's web client. See web.h. */
#include "web.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* Only these files are ever served, so request paths never touch the filesystem. */
static struct asset {
    const char *path, *file, *type;
    char *data;
    size_t len;
} assets[] = {
    { "/", "index.html", "text/html; charset=utf-8", NULL, 0 },
    { "/style.css", "style.css", "text/css; charset=utf-8", NULL, 0 },
    { "/app.js", "app.js", "text/javascript; charset=utf-8", NULL, 0 },
    { "/hush.js", "hush.js", "text/javascript; charset=utf-8", NULL, 0 },
    { "/sodium.mjs", "sodium.mjs", "text/javascript; charset=utf-8", NULL, 0 },
    { "/libsodium.mjs", "libsodium.mjs", "text/javascript; charset=utf-8", NULL, 0 },
};

/* Sent with every response. The page only loads its own scripts and styles,
 * shows images only from decrypted in-page data (blob: URLs), only connects
 * back to this server, and can't be framed by other sites. */
static const char security_headers[] =
    "Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; "
    "style-src 'self'; img-src blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "X-Frame-Options: DENY\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "Cross-Origin-Opener-Policy: same-origin\r\n"
    "Cross-Origin-Resource-Policy: same-origin\r\n"
    "Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n";

__attribute__((format(printf, 2, 3))) static void buf_printf(struct buf *b, const char *fmt, ...)
{
    char tmp[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n > 0)
        buf_put(b, tmp, (size_t)n < sizeof tmp ? (size_t)n : sizeof tmp - 1);
}

int web_load(const char *dir)
{
    for (size_t i = 0; i < sizeof assets / sizeof *assets; i++) {
        char path[4200];
        snprintf(path, sizeof path, "%s/%s", dir, assets[i].file);
        FILE *f = fopen(path, "rb");
        if (!f)
            return -1;
        struct buf b = { 0 };
        size_t r;
        do {
            buf_reserve(&b, 65536);
            r = fread(b.data + b.len, 1, b.cap - b.len, f);
            b.len += r;
        } while (r > 0 && b.len < (8u << 20));
        int err = ferror(f);
        fclose(f);
        if (err || b.len >= (8u << 20)) {
            buf_free(&b);
            errno = err ? EIO : EFBIG;
            return -1;
        }
        free(assets[i].data);
        assets[i].data = (char *)b.data;
        assets[i].len = b.len;
    }
    return 0;
}

/* ---- request parsing ------------------------------------------------------ */

static int copy_value(char *dst, size_t cap, const char *v)
{
    size_t n = strlen(v);
    if (n >= cap)
        return -1;
    memcpy(dst, v, n + 1);
    return 0;
}

static int is_tchar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c && strchr("!#$%&'*+-.^_`|~", c));
}

int http_parse(const uint8_t *buf, size_t len, struct http_req *req)
{
    size_t lim = len < HTTP_MAX_HEADER ? len : HTTP_MAX_HEADER;
    const uint8_t *end = memmem(buf, lim, "\r\n\r\n", 4);
    if (!end)
        return len >= HTTP_MAX_HEADER ? -1 : 0;
    size_t hl = (size_t)(end - buf);
    memset(req, 0, sizeof *req);

    /* No NULs or control bytes, and line breaks only as CRLF. */
    char head[HTTP_MAX_HEADER + 1];
    for (size_t i = 0; i < hl; i++) {
        uint8_t c = buf[i];
        if (c == '\r' && (i + 1 >= hl || buf[i + 1] != '\n'))
            return -1;
        if (c == '\n' && (i == 0 || buf[i - 1] != '\r'))
            return -1;
        if ((c < 0x20 && c != '\t' && c != '\r' && c != '\n') || c == 0x7f)
            return -1;
    }
    memcpy(head, buf, hl);
    head[hl] = '\0';

    /* Request line: METHOD SP target SP HTTP/1.x */
    char *line = head, *next = strstr(line, "\r\n");
    if (next)
        *next = '\0';
    char *sp1 = strchr(line, ' '), *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
    if (!sp1 || !sp2 || strchr(sp2 + 1, ' '))
        return -1;
    *sp1 = *sp2 = '\0';
    const char *method = line, *target = sp1 + 1, *version = sp2 + 1;
    if (strcmp(version, "HTTP/1.1") && strcmp(version, "HTTP/1.0"))
        return -1;
    req->get = !strcmp(method, "GET") || !strcmp(method, "HEAD");
    req->head = !strcmp(method, "HEAD");
    if (target[0] != '/')
        return -1;
    size_t tl = strcspn(target, "?#");
    if (tl < sizeof req->path) { /* longer paths stay "" and get a 404 */
        memcpy(req->path, target, tl);
        req->path[tl] = '\0';
    }

    int seen_host = 0, seen_xff = 0;
    for (line = next ? next + 2 : NULL; line && *line; line = next ? next + 2 : NULL) {
        next = strstr(line, "\r\n");
        if (next)
            *next = '\0';
        if (*line == ' ' || *line == '\t') /* obsolete line folding */
            return -1;
        char *colon = strchr(line, ':');
        if (!colon || colon == line)
            return -1;
        for (char *p = line; p < colon; p++)
            if (!is_tchar(*p))
                return -1;
        *colon = '\0';
        char *v = colon + 1;
        v += strspn(v, " \t");
        for (char *e = v + strlen(v); e > v && (e[-1] == ' ' || e[-1] == '\t');)
            *--e = '\0';

        int bad = 0;
        if (!strcasecmp(line, "Host"))
            bad = seen_host++ || copy_value(req->host, sizeof req->host, v);
        else if (!strcasecmp(line, "Origin"))
            bad = copy_value(req->origin, sizeof req->origin, v);
        else if (!strcasecmp(line, "X-Forwarded-For"))
            bad = seen_xff++ || copy_value(req->xff, sizeof req->xff, v);
        else if (!strcasecmp(line, "Sec-WebSocket-Key"))
            bad = copy_value(req->ws_key, sizeof req->ws_key, v);
        else if (!strcasecmp(line, "Sec-WebSocket-Version"))
            bad = copy_value(req->ws_version, sizeof req->ws_version, v);
        else if (!strcasecmp(line, "Upgrade"))
            req->upgrade = !strcasecmp(v, "websocket");
        if (bad)
            return -1;
    }
    return (int)(hl + 4);
}

/* ---- responses ------------------------------------------------------------- */

static const char *status_text(int code)
{
    switch (code) {
    case 101: return "Switching Protocols";
    case 200: return "OK";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 426: return "Upgrade Required";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    default: return "Service Unavailable";
    }
}

void http_error(struct buf *out, int code)
{
    char body[64];
    int n = snprintf(body, sizeof body, "%d %s\n", code, status_text(code));
    buf_printf(out,
               "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\n"
               "Content-Length: %d\r\nCache-Control: no-store\r\n%s%s%sConnection: close\r\n\r\n%s",
               code, status_text(code), n, security_headers,
               code == 405 ? "Allow: GET, HEAD\r\n" : "",
               code == 426 ? "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n" : "", body);
}

void http_serve(struct buf *out, const struct http_req *req)
{
    if (!req->get) {
        http_error(out, 405);
        return;
    }
    const struct asset *a = NULL;
    for (size_t i = 0; i < sizeof assets / sizeof *assets && !a; i++)
        if (assets[i].data && !strcmp(req->path, assets[i].path))
            a = &assets[i];
    if (!a) {
        http_error(out, 404);
        return;
    }
    buf_printf(out,
               "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
               "Cache-Control: no-cache\r\n%sConnection: close\r\n\r\n",
               a->type, a->len, security_headers);
    if (!req->head)
        buf_put(out, a->data, a->len);
}

/* ---- WebSocket ------------------------------------------------------------- */

static uint32_t rol(uint32_t x, int n)
{
    return x << n | x >> (32 - n);
}

/* SHA-1 is only used for the handshake's Sec-WebSocket-Accept value, which
 * RFC 6455 defines with it. It protects nothing. msg must be under 120 bytes. */
static void sha1(const uint8_t *msg, size_t len, uint8_t out[20])
{
    uint8_t m[128] = { 0 };
    size_t blocks = len + 9 > 64 ? 2 : 1;
    memcpy(m, msg, len);
    m[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        m[blocks * 64 - 1 - i] = (uint8_t)(bits >> (8 * i));

    uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    for (size_t blk = 0; blk < blocks; blk++) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) {
            const uint8_t *p = m + blk * 64 + i * 4;
            w[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
        }
        for (int i = 16; i < 80; i++)
            w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20)
                f = (b & c) | (~b & d), k = 0x5A827999;
            else if (i < 40)
                f = b ^ c ^ d, k = 0x6ED9EBA1;
            else if (i < 60)
                f = (b & c) | (b & d) | (c & d), k = 0x8F1BBCDC;
            else
                f = b ^ c ^ d, k = 0xCA62C1D6;
            uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d, d = c, c = rol(b, 30), b = a, a = t;
        }
        h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e;
    }
    for (int i = 0; i < 20; i++)
        out[i] = (uint8_t)(h[i / 4] >> (24 - 8 * (i % 4)));
}

/* The Origin header must name this same host, so other websites can't
 * open a connection from a visitor's browser. */
static int same_origin(const struct http_req *req)
{
    const char *o = req->origin;
    if (!*req->host)
        return 0;
    if (!strncmp(o, "https://", 8))
        o += 8;
    else if (!strncmp(o, "http://", 7))
        o += 7;
    else
        return 0;
    return !strcasecmp(o, req->host);
}

int ws_upgrade(struct buf *out, const struct http_req *req)
{
    uint8_t nonce[16];
    size_t nl;
    if (!req->get || req->head) {
        http_error(out, 405);
        return 0;
    }
    if (!req->upgrade || strcmp(req->ws_version, "13")) {
        http_error(out, 426);
        return 0;
    }
    if (sodium_base642bin(nonce, sizeof nonce, req->ws_key, strlen(req->ws_key), NULL, &nl,
                          NULL, sodium_base64_VARIANT_ORIGINAL) != 0 || nl != sizeof nonce) {
        http_error(out, 400);
        return 0;
    }
    if (!same_origin(req)) {
        http_error(out, 403);
        return 0;
    }
    char msg[sizeof req->ws_key + sizeof WS_GUID];
    uint8_t digest[20];
    char accept[sodium_base64_ENCODED_LEN(20, sodium_base64_VARIANT_ORIGINAL)];
    int n = snprintf(msg, sizeof msg, "%s%s", req->ws_key, WS_GUID);
    sha1((const uint8_t *)msg, (size_t)n, digest);
    sodium_bin2base64(accept, sizeof accept, digest, sizeof digest, sodium_base64_VARIANT_ORIGINAL);
    buf_printf(out,
               "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Accept: %s\r\n\r\n",
               accept);
    return 1;
}

int ws_peek(struct buf *b, int *opcode, uint8_t **payload, size_t *len, size_t *frame_size,
            size_t max)
{
    uint8_t *d = b->data;
    if (b->len < 2)
        return 0;
    /* Clients must mask their frames, set no reserved bits, and (here) not fragment. */
    if (!(d[0] & 0x80) || (d[0] & 0x70) || !(d[1] & 0x80))
        return -1;
    int op = d[0] & 0x0f;
    uint64_t n = d[1] & 0x7f;
    size_t h = 2;
    if (n == 126) {
        if (b->len < 4)
            return 0;
        n = (uint64_t)d[2] << 8 | d[3];
        h = 4;
    } else if (n == 127) {
        if (b->len < 10)
            return 0;
        n = 0;
        for (int i = 0; i < 8; i++)
            n = n << 8 | d[2 + i];
        h = 10;
    }
    if (n > max || (op >= 8 && n > 125))
        return -1;
    if (b->len < h + 4 + n)
        return 0;
    const uint8_t *mask = d + h;
    uint8_t *p = d + h + 4;
    for (size_t i = 0; i < n; i++)
        p[i] ^= mask[i & 3];
    *opcode = op;
    *payload = p;
    *len = (size_t)n;
    *frame_size = h + 4 + (size_t)n;
    return 1;
}

void ws_put(struct buf *out, int opcode, const void *a, size_t na, const void *b, size_t nb)
{
    uint64_t n = na + nb;
    uint8_t h[10];
    size_t hl;
    h[0] = (uint8_t)(0x80 | opcode);
    if (n < 126) {
        h[1] = (uint8_t)n;
        hl = 2;
    } else if (n < 65536) {
        h[1] = 126;
        h[2] = (uint8_t)(n >> 8);
        h[3] = (uint8_t)n;
        hl = 4;
    } else {
        h[1] = 127;
        for (int i = 0; i < 8; i++)
            h[2 + i] = (uint8_t)(n >> (56 - 8 * i));
        hl = 10;
    }
    buf_put(out, h, hl);
    buf_put(out, a, na);
    buf_put(out, b, nb);
}
