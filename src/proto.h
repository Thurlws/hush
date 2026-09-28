/* Shared wire format for hush (client) and hushd (relay server).
 *
 * Every frame is: u32 big-endian length | u8 type | payload
 * where length covers type + payload.
 *
 * Browsers send the same frames without the length, one per binary
 * WebSocket message.
 *
 * Handshake (client -> server -> client):
 *   HELLO     name, ed25519 public key, chat key
 *   CHALLENGE 32 random bytes
 *   AUTH      ed25519 signature over HUSH_AUTH_CONTEXT || challenge
 *   WELCOME   chat label, followed by one PEER per user already in that chat
 *
 * The chat key only gets you into a chat: the server admin creates it with
 * `hushd newkey` and the server keeps just its hash. After the handshake
 * the server only relays SEND -> DELIVER between people in the same chat.
 * The blob inside is nonce || crypto_box ciphertext, which the server
 * cannot read.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sodium.h>

#define HUSH_DEFAULT_PORT  "7777"
#define HUSH_DEFAULT_WEB   "8080"
#define HUSH_MAX_FRAME     (64 * 1024)
#define HUSH_NAME_MAX      24
#define HUSH_CHALLENGE_LEN 32
#define HUSH_AUTH_CONTEXT  "hush-auth-v2"
#define HUSH_KEY_MAX       64 /* chat key as typed, dashes and spaces allowed */
#define HUSH_FP_LEN        40 /* 32 hex digits in groups of 4, plus NUL */

enum {
    /* client -> server */
    T_HELLO = 1,     /* name, pk[32], u8 len + chat key */
    T_AUTH = 2,      /* sig[64] */
    T_SEND = 3,      /* to-name, blob */
    /* server -> client */
    T_CHALLENGE = 10, /* challenge[32] */
    T_WELCOME = 11,   /* chat label (same rules as a name) */
    T_PEER = 12,      /* name, pk[32], u8 just_joined */
    T_LEAVE = 13,     /* name */
    T_DELIVER = 14,   /* from-name, blob */
    T_ERROR = 15,     /* utf-8 text */
};

struct buf {
    uint8_t *data;
    size_t len, cap;
};

void buf_reserve(struct buf *b, size_t extra);
void buf_put(struct buf *b, const void *p, size_t n);
void buf_consume(struct buf *b, size_t n);
void buf_free(struct buf *b);

void frame_put(struct buf *out, uint8_t type, const void *payload, size_t n);
/* 1: a whole frame is buffered (drop it afterwards with buf_consume(b, *frame_size)),
 * 0: need more bytes, -1: malformed or oversized frame. */
int frame_peek(const struct buf *b, uint8_t *type, const uint8_t **payload,
               size_t *len, size_t *frame_size);

/* Names (and chat labels) are 1..HUSH_NAME_MAX of [A-Za-z0-9_.-] and go on the wire as u8 len + bytes. */
int name_valid(const char *s, size_t n);
int name_get(const uint8_t *p, size_t n, char out[HUSH_NAME_MAX + 1]);
void name_put(struct buf *b, const char *name);

void put_u64(uint8_t *p, uint64_t v);
uint64_t get_u64(const uint8_t *p);

void fingerprint(const uint8_t pk[crypto_sign_PUBLICKEYBYTES], char out[HUSH_FP_LEN]);

__attribute__((noreturn, format(printf, 1, 2))) void die(const char *fmt, ...);
