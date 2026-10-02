# Cryptography in hush

The short version first, then the exact constructions. Everything comes from
libsodium: the system library for the C programs, and
[libsodium.js](https://github.com/jedisct1/libsodium.js) 0.8.4 (sumo build, vendored
in `web/`) for the browser. hush doesn't implement any primitive itself. The one
exception is a small SHA-1 that only computes the WebSocket handshake's
`Sec-WebSocket-Accept` header, which protects nothing.

## In plain English

A chat key like `k3x7-9fqa` is the shared secret of one chat. Your client turns it
into two unrelated values. One is a login token, the only thing the server ever
sees, and it stores only a hash of that. The other is the key that encrypts the
chat's messages, which never leaves the clients.

Each person also has an identity key pair, made on their device the first time they
run hush. It proves who they are when logging in and signs every message they send.
Its fingerprint (`6937 b1d5 ...`) is what people compare on a call to know they're
talking to each other and not to someone the server slipped in.

Messages to the chat are encrypted with the chat key, so anyone with the key can read
the whole history, including what was said before they joined. Private messages are
encrypted between the two people's identity keys, so nobody else in the chat can
read them. Images get a fresh key each, which travels inside the message.

Clients remember the first identity key they see for each name. If it ever changes,
they say so loudly and stop trusting that name until the user accepts the new key.

## Chat keys

A chat key is 8 characters from `0123456789abcdefghjkmnpqrstvwxyz`, which is 40 random
bits, picked with libsodium's `randombytes_uniform`. When reading a key, case, dashes
and spaces don't matter, and `o`, `i` and `l` count as `0`, `1` and `1`.

40 bits is easy to share and easy to guess, so the key is stretched before anything
is derived from it:

```
master  = Argon2id(key, salt "hush-chat-key-v4", 3 passes, 128 MiB) -> 64 bytes
token   = BLAKE2b-256(master, key "hush-chat-login-v4")
chatkey = BLAKE2b-256(master, key "hush-chat-crypt-v4")
```

The salt is fixed so that every client derives the same values from the same key.
That's fine here because each guess has to pay for Argon2id on its own. On a Ryzen 7
7800X3D one derivation takes about 100 ms, so trying all 2^40 keys costs around
3,400 CPU-years, and every attempt needs 128 MiB of memory.

Keys made before keys got shorter have 24 characters (120 bits). They're used without
Argon2id, with `hush-chat-login-v3` and `hush-chat-crypt-v3` as the BLAKE2b keys.

The server stores `BLAKE2b-256(token, key "hush-chat-verify-v3")` in
`hushd-keys.txt`, a `0600` file, and compares the token from each login against it.
The token itself is never written down, and neither is the chat key.

Each chat also has an id, `BLAKE2b-256(chatkey)`, which goes into every message
signature so a message can't be moved from one chat to another.

## Identity keys

Each person has an Ed25519 key pair. The terminal client keeps the 64-byte secret key
in `~/.local/share/hush/identity.key` (mode `0600`), and the browser keeps it in local
storage. Neither leaves the device. The fingerprint is `BLAKE2b-128(public key)`,
shown as 8 groups of 4 hex digits.

To log in, the client signs `hush-auth-v3 || challenge` with its identity key, where
the challenge is 32 random bytes from the server. The server checks the signature
against the public key the client sent, and the first public key to use a name owns
it on that server for good (until the operator runs `hushd forget`).

For private messages the same key pair is converted to X25519 with libsodium's
`crypto_sign_ed25519_*_to_curve25519`. libsodium supports this, though it suggests
separate key pairs where possible. hush trades that for each person having one
fingerprint to verify instead of two.

## Messages

Every message is this plaintext:

```
u8 version (3) | u8 kind | u64 time (ms, sender's clock) | 16 random bytes |
sender name | recipient name (empty for the chat) | content |
Ed25519 signature over  "hush-msg-v3" || chat id || everything above
```

Content is UTF-8 text (kind 0) or an image reference (kind 1, see below).

A chat message is encrypted with XChaCha20-Poly1305 (IETF) under the chat key. A
private message uses `crypto_box`, which is X25519 for the shared key and
XSalsa20-Poly1305 for the encryption, between the sender's and recipient's converted
identity keys. Either way the body on the wire is a random 24-byte nonce followed by
the ciphertext. Nonces are random because 24 bytes is enough that two messages
under the same key won't collide, so there's no counter to keep in sync across
devices.

When a client receives a message it:

1. refuses it if the sender is unknown, or if the sender's key changed and the user
   hasn't accepted the new one,
2. decrypts it (a wrong key or any change to the ciphertext fails here),
3. checks the plaintext version and layout,
4. checks that the sender and recipient inside the plaintext match what the server
   says, so the server can't relabel a message,
5. checks the signature with the sender's pinned key, and
6. drops it if it has already seen those 16 random bytes, which stops replays.

Anything that fails is dropped with a warning saying why.

## Images

Each image gets a fresh random key from `crypto_aead_xchacha20poly1305_ietf_keygen`.
The image is encrypted with XChaCha20-Poly1305 under that key and uploaded as
`nonce | ciphertext`, and the server files it under a random 16-byte id. The message
that announces it carries the key, the id, the size, width, height, MIME type and
caption:

```
file key (32) | blob id (16) | u32 size | u16 width | u16 height | u8 len + MIME type | caption
```

That message is encrypted and signed like any other, so only people who can read the
message can decrypt the image, and the server only sees an opaque blob. Only JPEG,
PNG, GIF and WebP are shown.

Before sending, the terminal client removes metadata blocks: EXIF, XMP, IPTC and
comments from JPEGs, the text, time and EXIF chunks from PNGs, and EXIF and XMP from
WebP. The browser redraws photos on a canvas instead, so only the pixels survive.
GIFs are sent as they are to stay animated.

## Key pinning and verification

Clients keep every name's first identity key, in `known_peers` next to the terminal
identity or in local storage in the browser. When the server announces a different
key for a name, the client warns, shows both fingerprints, won't show that person's
messages and won't encrypt DMs to them, until the user runs `/trust NAME`.

Pinning on first sight trusts the server the first time. Comparing fingerprints out of
band (on a call, in person) and running `/verify NAME` removes that trust: after that,
the server can't swap in its own key without the warning.

## What isn't protected

The server sees who is in which chat, who sends to whom, when, and how big each
message and image is. Anyone who gets the chat key can read the chat's whole history,
and there's no forward secrecy, so a key that leaks later still opens old messages.
Identity and chat keys are stored unencrypted on the device. The browser runs whatever
JavaScript the server sends. [THREAT_MODEL.md](THREAT_MODEL.md) goes through what that
means in practice.
