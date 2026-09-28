/* Opening stored messages (the plaintext layout is described in proto.h).
 * Shared by the terminal client and hushd's export. */
#pragma once

#include "proto.h"

#include <stdio.h>

#define MSG_NONCE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define MSG_MAC   crypto_aead_xchacha20poly1305_ietf_ABYTES
#define MSG_HEAD  (1 + 1 + 8 + 16) /* version, kind, time, id */
#define MSG_PLAIN_MAX (MSG_HEAD + 2 * (1 + HUSH_NAME_MAX) + 100 + HUSH_MAX_TEXT + crypto_sign_BYTES)

struct hush_msg {
    int kind;
    uint64_t time; /* ms, as the sender's clock said */
    const uint8_t *uid;
    char from[HUSH_NAME_MAX + 1], to[HUSH_NAME_MAX + 1];
    const uint8_t *content;
    size_t content_len;
    size_t signed_len; /* the signature follows these bytes */
};

struct hush_image {
    const uint8_t *file_key, *blob;
    uint32_t size;
    uint16_t width, height;
    char mime[32];
    const uint8_t *caption;
    size_t caption_len;
};

/* Decrypt a message body (nonce | ciphertext) into out, which must hold
 * n bytes: with the chat key, or for a DM with the pair's crypto_box key.
 * Returns the plaintext length, or -1. */
long msg_decrypt(const uint8_t *body, size_t n, const uint8_t chat_key[32], const uint8_t *dm_key,
                 uint8_t *out);
/* Split a plaintext into its parts. Returns -1 if it's malformed. */
int msg_parse(const uint8_t *plain, size_t n, struct hush_msg *m);
/* Check the sender's signature over a parsed message. */
int msg_verify(const uint8_t *plain, const struct hush_msg *m, const uint8_t chat_id[32],
               const uint8_t pk[crypto_sign_PUBLICKEYBYTES]);
/* Read an image message's content. Returns -1 if malformed or not a supported type. */
int image_parse(const uint8_t *c, size_t n, struct hush_image *im);
const char *image_ext(const char *mime);

/* Write s as a JSON string: quoted, escaped, invalid UTF-8 replaced. */
void json_string(FILE *f, const uint8_t *s, size_t n);
