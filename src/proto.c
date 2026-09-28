#include "proto.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("hush: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

void buf_reserve(struct buf *b, size_t extra)
{
    if (b->len + extra <= b->cap)
        return;
    size_t cap = b->cap ? b->cap : 4096;
    while (cap < b->len + extra)
        cap *= 2;
    uint8_t *p = realloc(b->data, cap);
    if (!p)
        die("out of memory");
    b->data = p;
    b->cap = cap;
}

void buf_put(struct buf *b, const void *p, size_t n)
{
    if (!n)
        return;
    buf_reserve(b, n);
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

void buf_consume(struct buf *b, size_t n)
{
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

void buf_free(struct buf *b)
{
    free(b->data);
    memset(b, 0, sizeof *b);
}

void frame_put(struct buf *out, uint8_t type, const void *payload, size_t n)
{
    uint32_t len = (uint32_t)n + 1;
    uint8_t hdr[5] = { len >> 24, len >> 16, len >> 8, len, type };
    buf_put(out, hdr, sizeof hdr);
    buf_put(out, payload, n);
}

int frame_peek(const struct buf *b, uint8_t *type, const uint8_t **payload,
               size_t *len, size_t *frame_size)
{
    if (b->len < 4)
        return 0;
    const uint8_t *d = b->data;
    uint32_t n = (uint32_t)d[0] << 24 | (uint32_t)d[1] << 16 | (uint32_t)d[2] << 8 | d[3];
    if (n < 1 || n > HUSH_MAX_FRAME)
        return -1;
    if (b->len < 4 + (size_t)n)
        return 0;
    *type = d[4];
    *payload = d + 5;
    *len = n - 1;
    *frame_size = 4 + (size_t)n;
    return 1;
}

int name_valid(const char *s, size_t n)
{
    if (n < 1 || n > HUSH_NAME_MAX)
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

int name_get(const uint8_t *p, size_t n, char out[HUSH_NAME_MAX + 1])
{
    if (n < 1 || p[0] > n - 1 || !name_valid((const char *)p + 1, p[0]))
        return -1;
    memcpy(out, p + 1, p[0]);
    out[p[0]] = '\0';
    return 1 + p[0];
}

int name_get_opt(const uint8_t *p, size_t n, char out[HUSH_NAME_MAX + 1])
{
    if (n >= 1 && p[0] == 0) {
        out[0] = '\0';
        return 1;
    }
    return name_get(p, n, out);
}

void name_put(struct buf *b, const char *name)
{
    uint8_t n = (uint8_t)strlen(name);
    buf_put(b, &n, 1);
    buf_put(b, name, n);
}

void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

void put_u32(uint8_t *p, uint32_t v)
{
    for (int i = 3; i >= 0; i--, v >>= 8)
        p[i] = (uint8_t)v;
}

uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

void put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--, v >>= 8)
        p[i] = (uint8_t)v;
}

uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = v << 8 | p[i];
    return v;
}

void fingerprint(const uint8_t pk[crypto_sign_PUBLICKEYBYTES], char out[HUSH_FP_LEN])
{
    uint8_t h[16];
    char hex[sizeof h * 2 + 1];
    crypto_generichash(h, sizeof h, pk, crypto_sign_PUBLICKEYBYTES, NULL, 0);
    sodium_bin2hex(hex, sizeof hex, h, sizeof h);
    char *o = out;
    for (int i = 0; hex[i]; i++) {
        if (i && i % 4 == 0)
            *o++ = ' ';
        *o++ = hex[i];
    }
    *o = '\0';
}

static const char key_alphabet[] = "0123456789abcdefghjkmnpqrstvwxyz";

int chat_key_derive(const char *key, size_t n, uint8_t token[32], uint8_t chat_key[32])
{
    char norm[HUSH_KEY_CHARS_OLD];
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        char ch = (char)tolower((unsigned char)key[i]);
        if (ch == '-' || ch == ' ')
            continue;
        if (ch == 'o')
            ch = '0';
        else if (ch == 'i' || ch == 'l')
            ch = '1';
        if (!ch || !strchr(key_alphabet, ch) || k == HUSH_KEY_CHARS_OLD)
            return -1;
        norm[k++] = ch;
    }
    /* Different BLAKE2b keys make the two outputs unrelated. */
    if (k == HUSH_KEY_CHARS_OLD) {
        if (token)
            crypto_generichash(token, 32, (const uint8_t *)norm, k, (const uint8_t *)"hush-chat-login-v3", 18);
        if (chat_key)
            crypto_generichash(chat_key, 32, (const uint8_t *)norm, k, (const uint8_t *)"hush-chat-crypt-v3", 18);
    } else if (k == HUSH_KEY_CHARS) {
        /* 40 bits is little, so every guess has to pay for Argon2id. The salt
         * is fixed so that every client gets the same keys. */
        uint8_t master[64];
        if (crypto_pwhash(master, sizeof master, norm, k, (const uint8_t *)"hush-chat-key-v4", 3, 128u << 20,
                          crypto_pwhash_ALG_ARGON2ID13) != 0)
            return -2;
        if (token)
            crypto_generichash(token, 32, master, sizeof master, (const uint8_t *)"hush-chat-login-v4", 18);
        if (chat_key)
            crypto_generichash(chat_key, 32, master, sizeof master, (const uint8_t *)"hush-chat-crypt-v4", 18);
        sodium_memzero(master, sizeof master);
    } else {
        return -1;
    }
    sodium_memzero(norm, sizeof norm);
    return 0;
}

void chat_key_new(char out[HUSH_KEY_CHARS + HUSH_KEY_CHARS / 4])
{
    char *o = out;
    for (int i = 0; i < HUSH_KEY_CHARS; i++) {
        if (i && i % 4 == 0)
            *o++ = '-';
        *o++ = key_alphabet[randombytes_uniform(sizeof key_alphabet - 1)];
    }
    *o = '\0';
}

void chat_verifier(const uint8_t token[32], uint8_t out[32])
{
    crypto_generichash(out, 32, token, 32, (const uint8_t *)"hush-chat-verify-v3", 19);
}
