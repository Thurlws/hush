/* Unit tests for the parts that need no network: framing, names, chat keys,
 * message crypto and parsing, HTTP and WebSocket. Expected values marked
 * "from JS" or "from Python" come from web/hush.js and hashlib, so the
 * clients can't drift apart without this failing. */
#include "msg.h"
#include "proto.h"
#include "web.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, fails;

#define CHECK(cond)                                                  \
    do {                                                             \
        checks++;                                                    \
        if (!(cond)) {                                               \
            fails++;                                                 \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
        }                                                            \
    } while (0)

static int hex_is(const uint8_t *b, size_t n, const char *hex)
{
    char h[129];
    sodium_bin2hex(h, sizeof h, b, n);
    return !strcmp(h, hex);
}

static void test_frames(void)
{
    struct buf b = { 0 };
    uint8_t type;
    const uint8_t *p;
    size_t n, fs;

    frame_put(&b, T_POST, "abc", 3);
    CHECK(b.len == 8);
    CHECK(frame_peek(&b, &type, &p, &n, &fs) == 1);
    CHECK(type == T_POST && n == 3 && !memcmp(p, "abc", 3) && fs == 8);
    for (size_t cut = 0; cut < b.len; cut++) {
        struct buf part = { b.data, cut, b.cap };
        CHECK(frame_peek(&part, &type, &p, &n, &fs) == 0);
    }

    frame_put(&b, T_ADMIN, NULL, 0);
    buf_consume(&b, fs);
    CHECK(frame_peek(&b, &type, &p, &n, &fs) == 1 && type == T_ADMIN && n == 0 && fs == 5);

    uint8_t zero[5] = { 0 }, over[4] = { 0, 1, 0, 1 }, max[4] = { 0, 1, 0, 0 };
    struct buf z = { zero, sizeof zero, sizeof zero }, o = { over, 4, 4 }, m = { max, 4, 4 };
    CHECK(frame_peek(&z, &type, &p, &n, &fs) == -1); /* length 0 */
    CHECK(frame_peek(&o, &type, &p, &n, &fs) == -1); /* HUSH_MAX_FRAME + 1 */
    CHECK(frame_peek(&m, &type, &p, &n, &fs) == 0);  /* HUSH_MAX_FRAME is fine, just not here yet */
    buf_free(&b);
}

static void test_names(void)
{
    char out[HUSH_NAME_MAX + 1];
    CHECK(name_get((const uint8_t *)"\x05" "alice", 6, out) == 6 && !strcmp(out, "alice"));
    CHECK(name_get((const uint8_t *)"\x05" "alice", 5, out) == -1); /* length runs past the end */
    CHECK(name_get((const uint8_t *)"\x05" "al ce", 6, out) == -1);
    CHECK(name_get((const uint8_t *)"\x05" "al/ce", 6, out) == -1);
    CHECK(name_get((const uint8_t *)"\x06" "\xc3\xa5lice", 7, out) == -1);
    CHECK(name_get((const uint8_t *)"\x00", 1, out) == -1);
    CHECK(name_get_opt((const uint8_t *)"\x00", 1, out) == 1 && !*out);
    CHECK(name_get((const uint8_t *)"", 0, out) == -1);
    CHECK(name_get_opt((const uint8_t *)"", 0, out) == -1);
    CHECK(name_valid("a.b-c_D9", 8));
    CHECK(name_valid("abcdefghijklmnopqrstuvwx", 24));
    CHECK(!name_valid("abcdefghijklmnopqrstuvwxy", 25));

    struct buf b = { 0 };
    name_put(&b, "bob");
    CHECK(b.len == 4 && b.data[0] == 3 && name_get(b.data, b.len, out) == 4 && !strcmp(out, "bob"));
    buf_free(&b);
}

static void test_ints(void)
{
    uint8_t b[8];
    put_u16(b, 0xbeef);
    CHECK(get_u16(b) == 0xbeef && b[0] == 0xbe);
    put_u32(b, 0xdeadbeefu);
    CHECK(get_u32(b) == 0xdeadbeefu && b[0] == 0xde);
    put_u64(b, 0x0123456789abcdefull);
    CHECK(get_u64(b) == 0x0123456789abcdefull && b[0] == 0x01 && b[7] == 0xef);
}

static void test_keys(void)
{
    uint8_t tok[32], key[32], tok2[32], key2[32];
    /* 8-character keys go through Argon2id. From JS. */
    CHECK(chat_key_derive("k3x7-9fqa", 9, tok, key) == 0);
    CHECK(hex_is(tok, 32, "54ab3b2b345ed1d7444c3fb874f9a5a11b38ba4088ae79d64def3f50c5474013"));
    CHECK(hex_is(key, 32, "e33db6eb8937cbe3d0061c8bc04209c8f073830952ec7e6a01ae89d966041229"));
    CHECK(chat_key_derive("K3X7 9FQA", 9, tok2, key2) == 0 && !memcmp(tok, tok2, 32) && !memcmp(key, key2, 32));
    CHECK(chat_key_derive("ab01-cd1e", 9, tok, NULL) == 0 && chat_key_derive("abOI-cdLe", 9, tok2, NULL) == 0 &&
          !memcmp(tok, tok2, 32));

    /* Old 24-character keys skip Argon2id. From Python. */
    const char *old = "0123-4567-89ab-cdef-ghjk-mnpq";
    CHECK(chat_key_derive(old, strlen(old), tok, key) == 0);
    CHECK(hex_is(tok, 32, "3304eb3e367f7391bbe522de05fd63756c5989ece23b9dec49e254cd945097ef"));
    CHECK(hex_is(key, 32, "a9579aff1369f54b4b4a4b36ca12679c697ecc6df247bc60d25eb49385e4c149"));

    CHECK(chat_key_derive("k3x7-9fq", 8, NULL, NULL) == -1);   /* 7 characters */
    CHECK(chat_key_derive("k3x7-9fqab", 10, NULL, NULL) == -1); /* 9 */
    CHECK(chat_key_derive("k3x7-9fqu", 9, NULL, NULL) == -1);   /* u isn't in the alphabet */
    CHECK(chat_key_derive("0123-4567-89ab-cdef-ghjk-mnpqr", 30, NULL, NULL) == -1);

    char k[HUSH_KEY_CHARS + HUSH_KEY_CHARS / 4], k2[sizeof k];
    chat_key_new(k);
    chat_key_new(k2);
    CHECK(strlen(k) == 9 && k[4] == '-' && strcmp(k, k2));
    CHECK(chat_key_derive(k, strlen(k), NULL, NULL) == 0);

    uint8_t v1[32], v2[32];
    chat_verifier(tok, v1);
    chat_verifier(tok, v2);
    CHECK(!memcmp(v1, v2, 32) && memcmp(v1, tok, 32));

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    for (size_t i = 0; i < sizeof pk; i++)
        pk[i] = (uint8_t)i;
    char fp[HUSH_FP_LEN];
    fingerprint(pk, fp);
    CHECK(!strcmp(fp, "f39a 2cad 5841 1cd4 9f57 7e50 86b8 031f")); /* from Python */
}

struct party {
    uint8_t pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    uint8_t xpk[crypto_scalarmult_BYTES], xsk[crypto_scalarmult_BYTES];
};

static void party(struct party *p)
{
    crypto_sign_keypair(p->pk, p->sk);
    CHECK(crypto_sign_ed25519_pk_to_curve25519(p->xpk, p->pk) == 0);
    CHECK(crypto_sign_ed25519_sk_to_curve25519(p->xsk, p->sk) == 0);
}

/* A plaintext built the way client.c's post() does it. Returns its length. */
static size_t make_plain(uint8_t *out, int kind, const char *from, const char *to, const void *c, size_t cn,
                         const struct party *sender, const uint8_t chat_id[32])
{
    struct buf b = { 0 }, sd = { 0 };
    uint8_t head[MSG_HEAD] = { HUSH_MSG_VERSION, (uint8_t)kind };
    put_u64(head + 2, 1700000000000ull);
    randombytes_buf(head + 10, 16);
    buf_put(&b, head, sizeof head);
    name_put(&b, from);
    name_put(&b, to);
    buf_put(&b, c, cn);
    buf_put(&sd, HUSH_MSG_CONTEXT, sizeof HUSH_MSG_CONTEXT - 1);
    buf_put(&sd, chat_id, 32);
    buf_put(&sd, b.data, b.len);
    uint8_t sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, sd.data, sd.len, sender->sk);
    buf_put(&b, sig, sizeof sig);
    size_t n = b.len;
    memcpy(out, b.data, n);
    buf_free(&b);
    buf_free(&sd);
    return n;
}

static size_t seal_chat(uint8_t *out, const uint8_t *plain, size_t n, const uint8_t key[32])
{
    unsigned long long cl;
    randombytes_buf(out, MSG_NONCE);
    crypto_aead_xchacha20poly1305_ietf_encrypt(out + MSG_NONCE, &cl, plain, n, NULL, 0, NULL, out, key);
    return MSG_NONCE + (size_t)cl;
}

static void test_messages(void)
{
    struct party alice, bob, eve;
    party(&alice);
    party(&bob);
    party(&eve);
    uint8_t chat_key[32], chat_id[32], other_id[32], wrong[32];
    crypto_aead_xchacha20poly1305_ietf_keygen(chat_key);
    crypto_generichash(chat_id, 32, chat_key, 32, NULL, 0);
    randombytes_buf(other_id, sizeof other_id);
    memcpy(wrong, chat_key, 32);
    wrong[0] ^= 1;

    static uint8_t plain[MSG_PLAIN_MAX], body[MSG_PLAIN_MAX + 64], out[MSG_PLAIN_MAX + 64];
    struct hush_msg m;
    size_t pn = make_plain(plain, KIND_TEXT, "alice", "", "hi all", 6, &alice, chat_id);
    size_t bn = seal_chat(body, plain, pn, chat_key);

    CHECK(msg_decrypt(body, bn, chat_key, NULL, out) == (long)pn && !memcmp(out, plain, pn));
    CHECK(msg_parse(out, pn, &m) == 0);
    CHECK(m.kind == KIND_TEXT && m.time == 1700000000000ull && !strcmp(m.from, "alice") && !*m.to);
    CHECK(m.content_len == 6 && !memcmp(m.content, "hi all", 6));
    CHECK(msg_verify(out, &m, chat_id, alice.pk) == 0);
    CHECK(msg_verify(out, &m, chat_id, bob.pk) == -1);    /* someone else's key */
    CHECK(msg_verify(out, &m, other_id, alice.pk) == -1); /* replayed into another chat */

    CHECK(msg_decrypt(body, bn, wrong, NULL, out) == -1);
    body[bn - 1] ^= 1;
    CHECK(msg_decrypt(body, bn, chat_key, NULL, out) == -1); /* tampered ciphertext */
    body[bn - 1] ^= 1;
    body[0] ^= 1;
    CHECK(msg_decrypt(body, bn, chat_key, NULL, out) == -1); /* tampered nonce */
    body[0] ^= 1;
    CHECK(msg_decrypt(body, MSG_NONCE + MSG_MAC - 1, chat_key, NULL, out) == -1);

    memcpy(out, plain, pn);
    out[MSG_HEAD + 1] = 'b'; /* relabelled as "blice" */
    CHECK(msg_parse(out, pn, &m) == 0 && msg_verify(out, &m, chat_id, alice.pk) == -1);
    memcpy(out, plain, pn);
    out[pn - crypto_sign_BYTES - 1] ^= 1; /* text edited */
    CHECK(msg_parse(out, pn, &m) == 0 && msg_verify(out, &m, chat_id, alice.pk) == -1);

    memcpy(out, plain, pn);
    out[0] = 2; /* older plaintext version */
    CHECK(msg_parse(out, pn, &m) == -1);
    CHECK(msg_parse(plain, MSG_HEAD + 1 + crypto_sign_BYTES, &m) == -1);
    memcpy(out, plain, pn);
    out[MSG_HEAD] = 30; /* name longer than allowed */
    CHECK(msg_parse(out, pn, &m) == -1);

    /* DMs are crypto_box between the two, so neither the chat key nor a third key opens them */
    uint8_t ab[crypto_box_BEFORENMBYTES], ba[crypto_box_BEFORENMBYTES], ea[crypto_box_BEFORENMBYTES];
    CHECK(crypto_box_beforenm(ab, bob.xpk, alice.xsk) == 0 && crypto_box_beforenm(ba, alice.xpk, bob.xsk) == 0);
    CHECK(crypto_box_beforenm(ea, alice.xpk, eve.xsk) == 0);
    pn = make_plain(plain, KIND_TEXT, "alice", "bob", "psst", 4, &alice, chat_id);
    randombytes_buf(body, MSG_NONCE);
    crypto_box_easy_afternm(body + MSG_NONCE, plain, pn, body, ab);
    bn = MSG_NONCE + pn + crypto_box_MACBYTES;
    CHECK(msg_decrypt(body, bn, chat_key, ba, out) == (long)pn && !memcmp(out, plain, pn));
    CHECK(msg_parse(out, pn, &m) == 0 && !strcmp(m.to, "bob") && msg_verify(out, &m, chat_id, alice.pk) == 0);
    CHECK(msg_decrypt(body, bn, chat_key, NULL, out) == -1);
    CHECK(msg_decrypt(body, bn, chat_key, ea, out) == -1);
}

static void test_images(void)
{
    uint8_t c[200] = { 0 };
    struct hush_image im;
    put_u32(c + 48, 123456);
    put_u16(c + 52, 640);
    put_u16(c + 54, 480);
    c[56] = 10;
    memcpy(c + 57, "image/jpeg", 10);
    memcpy(c + 67, "the view", 8);
    CHECK(image_parse(c, 75, &im) == 0);
    CHECK(im.size == 123456 && im.width == 640 && im.height == 480 && !strcmp(im.mime, "image/jpeg"));
    CHECK(im.caption_len == 8 && !memcmp(im.caption, "the view", 8) && im.blob == c + 32);
    CHECK(image_parse(c, 66, &im) == -1); /* mime cut short */
    CHECK(image_parse(c, 56, &im) == -1);
    c[56] = 0;
    CHECK(image_parse(c, 75, &im) == -1);
    c[56] = 32;
    CHECK(image_parse(c, 120, &im) == -1);
    c[56] = 13;
    memcpy(c + 57, "image/svg+xml", 13);
    CHECK(image_parse(c, 75, &im) == -1); /* svg can carry script */
    CHECK(!strcmp(image_ext("image/webp"), "webp") && !image_ext("text/html"));
}

static void test_json(void)
{
    char *s = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&s, &n);
    /* quote, backslash, controls, valid é, then 0xff, an overlong slash and a surrogate */
    const char in[] = "a\"b\\c\n\x01" "\xc3\xa9" "\xff" "\xc0\xaf" "\xed\xa0\x80";
    json_string(f, (const uint8_t *)in, sizeof in - 1);
    fclose(f);
    CHECK(!strcmp(s, "\"a\\\"b\\\\c\\u000a\\u0001\xc3\xa9"
                     "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\""));
    free(s);
}

static int parse(const char *s, struct http_req *r)
{
    return http_parse((const uint8_t *)s, strlen(s), r);
}

static void test_http(void)
{
    struct http_req r;
    const char *ok = "GET /app.js?v=1 HTTP/1.1\r\nHost: chat.example.com\r\nX-Forwarded-For: 203.0.113.9\r\n\r\nextra";
    CHECK(parse(ok, &r) == (int)strlen(ok) - 5);
    CHECK(r.get && !r.head && !strcmp(r.path, "/app.js") && !strcmp(r.host, "chat.example.com"));
    CHECK(!strcmp(r.xff, "203.0.113.9"));
    CHECK(parse("HEAD / HTTP/1.0\r\n\r\n", &r) > 0 && r.get && r.head);
    CHECK(parse("POST / HTTP/1.1\r\n\r\n", &r) > 0 && !r.get);
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\n", &r) == 0);
    CHECK(parse("GET / HTTP/1.1\nHost: a\r\n\r\n", &r) == -1);     /* bare LF */
    CHECK(parse("GET / HTTP/1.1\r\nX: a\rb\r\n\r\n", &r) == -1);   /* bare CR */
    CHECK(parse("GET / HTTP/1.1\r\nX: a\x01" "b\r\n\r\n", &r) == -1);
    CHECK(parse("GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\n", &r) == -1); /* line folding */
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", &r) == -1);
    CHECK(parse("GET / HTTP/1.1\r\nX-Forwarded-For: a\r\nX-Forwarded-For: b\r\n\r\n", &r) == -1);
    CHECK(parse("GET / HTTP/1.1\r\nBad Name: a\r\n\r\n", &r) == -1);
    CHECK(parse("GET / HTTP/1.1\r\nNoColon\r\n\r\n", &r) == -1);
    CHECK(parse("GET / HTTP/2.0\r\n\r\n", &r) == -1);
    CHECK(parse("GET http://evil/ HTTP/1.1\r\n\r\n", &r) == -1);
    CHECK(parse("GET  / HTTP/1.1\r\n\r\n", &r) == -1);

    static char req[HTTP_MAX_HEADER + 64];
    snprintf(req, sizeof req, "GET /%0100d HTTP/1.1\r\n\r\n", 0);
    CHECK(parse(req, &r) > 0 && !*r.path); /* too long for any real file, so a 404 */
    snprintf(req, sizeof req, "GET / HTTP/1.1\r\nHost: %0300d\r\n\r\n", 0);
    CHECK(parse(req, &r) == -1);
    memset(req, 'a', HTTP_MAX_HEADER);
    CHECK(http_parse((const uint8_t *)req, HTTP_MAX_HEADER, &r) == -1);
    CHECK(http_parse((const uint8_t *)req, HTTP_MAX_HEADER - 1, &r) == 0);
}

/* Parse a WebSocket upgrade with extra headers and run ws_upgrade on it */
static int upgrade(const char *extra, struct buf *out)
{
    char req[1024];
    struct http_req r;
    snprintf(req, sizeof req, "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n%s\r\n", extra);
    out->len = 0;
    int k = parse(req, &r) > 0 ? ws_upgrade(out, &r) : -1;
    buf_put(out, "", 1);
    return k;
}

#define RFC_KEY "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"

static void test_ws_upgrade(void)
{
    struct buf out = { 0 };
    /* the example in RFC 6455 section 1.3 */
    CHECK(upgrade(RFC_KEY "Origin: http://example.com\r\n", &out) == 1);
    CHECK(strstr((char *)out.data, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != NULL);
    CHECK(upgrade(RFC_KEY "Origin: https://EXAMPLE.com\r\n", &out) == 1);
    CHECK(upgrade(RFC_KEY "Origin: https://evil.example\r\n", &out) == 0 && strstr((char *)out.data, " 403 "));
    CHECK(upgrade(RFC_KEY "Origin: http://example.com:8080\r\n", &out) == 0);
    CHECK(upgrade(RFC_KEY, &out) == 0);
    CHECK(upgrade("Sec-WebSocket-Version: 12\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                  "Origin: http://example.com\r\n", &out) == 0 && strstr((char *)out.data, " 426 "));
    CHECK(upgrade("Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: c2hvcnQ=\r\nOrigin: http://example.com\r\n",
                  &out) == 0 && strstr((char *)out.data, " 400 "));
    buf_free(&out);
}

/* A frame as a browser sends it: masked, FIN set unless fin is 0 */
static void client_frame(struct buf *b, int op, const uint8_t *p, size_t n, int fin)
{
    uint8_t h[14], mask[4] = { 0x12, 0x34, 0x56, 0x78 };
    size_t hl = 2;
    h[0] = (uint8_t)((fin ? 0x80 : 0) | op);
    if (n < 126) {
        h[1] = (uint8_t)(0x80 | n);
    } else if (n < 65536) {
        h[1] = 0x80 | 126;
        put_u16(h + 2, (uint16_t)n);
        hl = 4;
    } else {
        h[1] = 0x80 | 127;
        put_u64(h + 2, n);
        hl = 10;
    }
    memcpy(h + hl, mask, 4);
    buf_put(b, h, hl + 4);
    for (size_t i = 0; i < n; i++) {
        uint8_t c = (uint8_t)(p[i] ^ mask[i & 3]);
        buf_put(b, &c, 1);
    }
}

static void test_ws_frames(void)
{
    struct buf b = { 0 }, o = { 0 };
    int op;
    uint8_t *p;
    size_t n, fs;
    static uint8_t big[70000];
    memset(big, 'x', sizeof big);

    client_frame(&b, WS_BINARY, (const uint8_t *)"\x03hello", 6, 1);
    for (size_t cut = 0; cut < b.len; cut++) {
        struct buf part = { b.data, cut, b.cap };
        CHECK(ws_peek(&part, &op, &p, &n, &fs, 1000) == 0);
    }
    CHECK(ws_peek(&b, &op, &p, &n, &fs, 1000) == 1 && op == WS_BINARY && n == 6 && fs == b.len);
    CHECK(!memcmp(p, "\x03hello", 6));

    b.len = 0;
    client_frame(&b, WS_BINARY, big, 300, 1);
    CHECK(ws_peek(&b, &op, &p, &n, &fs, 1000) == 1 && n == 300 && p[299] == 'x');
    b.len = 0;
    client_frame(&b, WS_BINARY, big, sizeof big, 1);
    CHECK(ws_peek(&b, &op, &p, &n, &fs, HUSH_MAX_FRAME) == -1);
    CHECK(ws_peek(&b, &op, &p, &n, &fs, sizeof big) == 1 && n == sizeof big);
    b.len = 0;
    client_frame(&b, WS_BINARY, big, 10, 0);
    CHECK(ws_peek(&b, &op, &p, &n, &fs, 1000) == -1); /* fragments aren't supported */
    b.len = 0;
    client_frame(&b, WS_PING, big, 126, 1);
    CHECK(ws_peek(&b, &op, &p, &n, &fs, 1000) == -1); /* control frames are at most 125 bytes */
    b.len = 0;
    client_frame(&b, WS_BINARY, big, 10, 1);
    b.data[0] = (uint8_t)(b.data[0] | 0x40);
    CHECK(ws_peek(&b, &op, &p, &n, &fs, 1000) == -1); /* reserved bit */
    b.len = 0;
    client_frame(&b, WS_BINARY, big, 10, 1);
    b.data[1] = (uint8_t)(b.data[1] & 0x7f);
    CHECK(ws_peek(&b, &op, &p, &n, &fs, 1000) == -1); /* not masked */

    ws_put(&o, WS_BINARY, big, 125, NULL, 0);
    CHECK(o.len == 2 + 125 && o.data[0] == 0x82 && o.data[1] == 125);
    o.len = 0;
    ws_put(&o, WS_BINARY, "\x0e", 1, big, 125);
    CHECK(o.len == 4 + 126 && o.data[1] == 126 && get_u16(o.data + 2) == 126 && o.data[4] == 0x0e);
    o.len = 0;
    ws_put(&o, WS_BINARY, big, 65536, NULL, 0);
    CHECK(o.len == 10 + 65536 && o.data[1] == 127 && get_u64(o.data + 2) == 65536);
    buf_free(&o);
    buf_free(&b);
}

int main(void)
{
    if (sodium_init() < 0)
        die("libsodium failed to initialise");
    test_frames();
    test_names();
    test_ints();
    test_keys();
    test_messages();
    test_images();
    test_json();
    test_http();
    test_ws_upgrade();
    test_ws_frames();
    printf("unit: %d checks, %d failed\n", checks, fails);
    return fails != 0;
}
