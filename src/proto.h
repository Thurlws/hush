/* Shared wire format for hush (client) and hushd (server).
 *
 * Every frame is: u32 big-endian length | u8 type | payload
 * where length covers type + payload. Browsers send the same frames
 * without the length, one per binary WebSocket message.
 *
 * Chat keys. An admin makes one per chat (`hushd newkey`, or NEWCHAT from a
 * client). Clients derive two unrelated values from it: a login token, which
 * is all the server sees (it stores only a hash of it), and the chat's
 * encryption key, which never leaves the clients. 8-character keys (40 bits)
 * go through Argon2id first, so each guess against stolen server files is
 * slow. Older 24-character keys (120 bits) are used as they are.
 *
 * Handshake (client -> server -> client):
 *   HELLO     name, ed25519 public key, login token, protocol version
 *   CHALLENGE 32 random bytes
 *   AUTH      ed25519 signature over HUSH_AUTH_CONTEXT || challenge
 *   WELCOME   chat label, then one PEER for every member of the chat
 * Someone new to a chat gets WAITING instead and waits, seeing nothing,
 * until an admin approves them (then WELCOME follows) or denies them.
 * Admins are identity keys the operator listed by fingerprint. They get
 * PENDING for each person waiting and answer with DECIDE.
 * A HELLO with an all-zero token asks for no chat at all: only admins get
 * through (ADMIN instead of WELCOME), and can then only send NEWCHAT.
 *
 * After that, clients POST messages. The server stores them and sends a
 * MSG to everyone concerned who is online. HISTORY asks for stored ones.
 * Images are uploaded (UPLOAD) and downloaded (FETCH) as encrypted blobs.
 *
 * Message body (the blob in POST/MSG), which the server cannot read:
 *   chat message: nonce[24] | XChaCha20-Poly1305(chat key, plaintext)
 *   DM:           nonce[24] | crypto_box(sender <-> recipient, plaintext)
 * plaintext:
 *   u8 version (3) | u8 kind | u64 time (ms) | id[16] random |
 *   from (name) | to (name, empty for the chat) | content |
 *   ed25519 signature by the sender over
 *     HUSH_MSG_CONTEXT || chat id[32] || everything before the signature
 *   where chat id = BLAKE2b(chat key).
 * content, KIND_TEXT:  utf-8 text
 *          KIND_IMAGE: file key[32] | blob id[16] | u32 size | u16 width |
 *                      u16 height | u8 len + mime type | utf-8 caption
 * An image blob is nonce[24] | XChaCha20-Poly1305(file key, image bytes).
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sodium.h>

#define HUSH_VERSION       "0.1.0"
#define HUSH_DEFAULT_PORT  "7777"
#define HUSH_DEFAULT_WEB   "8080"
#define HUSH_MAX_FRAME     ((size_t)64 * 1024)
#define HUSH_NAME_MAX      24
#define HUSH_CHALLENGE_LEN 32
#define HUSH_AUTH_CONTEXT  "hush-auth-v3"
#define HUSH_MSG_CONTEXT   "hush-msg-v3"
#define HUSH_KEY_CHARS     8  /* chat key: Crockford base32, 40 random bits */
#define HUSH_KEY_CHARS_OLD 24 /* keys made before they got shorter: 120 bits */
#define HUSH_KEY_MAX       64 /* as typed, dashes and spaces allowed */
#define HUSH_FP_LEN        40 /* 32 hex digits in groups of 4, plus NUL */
#define HUSH_MAX_TEXT      4000
#define HUSH_MAX_IMAGE     (25u << 20)
#define HUSH_CHUNK         ((size_t)48 * 1024) /* upload/download piece */
#define HUSH_BLOB_ID       16
#define HUSH_HISTORY_MAX   200 /* messages per HISTORY request */
/* Protocol version, the last byte of HELLO. A HELLO without it is version 0,
 * from before versions. hushd refuses anything outside MIN..HUSH_PROTO, so
 * the first incompatible change bumps both. */
#define HUSH_PROTO         1
#define HUSH_PROTO_MIN     0

enum {
    /* client -> server */
    T_HELLO = 1,   /* name, pk[32], token[32], u8 version */
    T_AUTH = 2,    /* sig[64] */
    T_POST = 3,    /* to (name, empty for the chat), body */
    T_HISTORY = 4, /* u8 dir, u64 anchor id, u16 limit. dir 0: older than anchor (anchor 0 = newest),
                      1: newer, 2: newer, only messages you sent or that were sent to you */
    T_UPLOAD = 5,  /* u8 flags (UP_FIRST, UP_LAST), data */
    T_FETCH = 6,   /* blob id[16] */
    T_DECIDE = 7,  /* admins: u8 approve, name */
    T_NEWCHAT = 8, /* admins: chat label, login token[32] of a key the client made */
    /* server -> client */
    T_CHALLENGE = 10,   /* challenge[32] */
    T_WELCOME = 11,     /* chat label (same rules as a name), u8 flags (WELCOME_ADMIN) */
    T_PEER = 12,        /* name, pk[32], u8 flags (PEER_ONLINE, PEER_NEW) */
    T_LEAVE = 13,       /* name: went offline */
    T_MSG = 14,         /* u64 id, u64 server time (ms), u8 live, from, to, body */
    T_ERROR = 15,       /* utf-8 text */
    T_HISTORY_END = 16, /* u8 dir, u8 more */
    T_UPLOADED = 17,    /* blob id[16] */
    T_BLOB = 18,        /* blob id[16], u8 status (BLOB_*), data */
    T_WAITING = 19,     /* chat label: you're on the waitlist */
    T_PENDING = 20,     /* admins: u8 waiting (1) or decided (0), name, pk[32] */
    T_CREATED = 21,     /* admins: chat label, after NEWCHAT */
    T_ADMIN = 22,       /* admins: logged in without a chat (empty) */
};

enum { PEER_ONLINE = 1, PEER_NEW = 2 };
enum { UP_FIRST = 1, UP_LAST = 2 };
enum { WELCOME_ADMIN = 1 };
enum { HIST_OLDER = 0, HIST_NEWER = 1, HIST_MINE = 2 };
enum { BLOB_PART = 0, BLOB_LAST = 1, BLOB_MISSING = 2 };
enum { KIND_TEXT = 0, KIND_IMAGE = 1 };
#define HUSH_MSG_VERSION 3

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

/* Names (and chat labels) are 1..HUSH_NAME_MAX of [A-Za-z0-9_.-], sent as
 * u8 len + bytes. name_get returns the bytes used, or -1. name_get_opt also
 * takes an empty name, meaning "the whole chat". */
int name_valid(const char *s, size_t n);
int name_get(const uint8_t *p, size_t n, char out[HUSH_NAME_MAX + 1]);
int name_get_opt(const uint8_t *p, size_t n, char out[HUSH_NAME_MAX + 1]);
void name_put(struct buf *b, const char *name);

void put_u16(uint8_t *p, uint16_t v);
void put_u32(uint8_t *p, uint32_t v);
void put_u64(uint8_t *p, uint64_t v);
uint16_t get_u16(const uint8_t *p);
uint32_t get_u32(const uint8_t *p);
uint64_t get_u64(const uint8_t *p);

void fingerprint(const uint8_t pk[crypto_sign_PUBLICKEYBYTES], char out[HUSH_FP_LEN]);

/* Read a chat key as typed (case, dashes and spaces don't matter, o/i/l
 * read as 0/1/1) and derive its login token and encryption key. Either
 * output may be NULL. Returns -1 if it isn't a key, -2 if Argon2id ran out
 * of memory. */
int chat_key_derive(const char *key, size_t n, uint8_t token[32], uint8_t chat_key[32]);
/* What the server stores for a login token. */
void chat_verifier(const uint8_t token[32], uint8_t out[32]);
/* A new random chat key, as xxxx-xxxx. */
void chat_key_new(char out[HUSH_KEY_CHARS + HUSH_KEY_CHARS / 4]);

__attribute__((noreturn, format(printf, 1, 2))) void die(const char *fmt, ...);
