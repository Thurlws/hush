# hush

End-to-end encrypted group chat for you and your friends, in C, in the terminal.

- `hushd` is a relay server. It forwards encrypted blobs and cannot read messages.
- `hush` is the client. It holds your keys, encrypts and decrypts messages, and shows the chat.

## Build

Needs a C compiler and [libsodium](https://libsodium.org) (`pacman -S libsodium`,
`apt install libsodium-dev`, `brew install libsodium`).

```sh
make
make install        # optional: copies both binaries to ~/.local/bin
./test.sh           # optional: end-to-end tests on localhost
```

## Run

One person hosts the server:

```sh
./hushd                      # listens on port 7777; -p to change it
sudo ufw allow 7777/tcp      # if you use a firewall
```

Friends need to reach that port. Pick one:

- Tailscale / ZeroTier (easiest): everyone joins the same tailnet and connects to the host's tailnet IP.
- Port forward: forward TCP 7777 on your router to the host and give friends your public IP.
- VPS: run `hushd` on any cheap server. Because of the end-to-end encryption, it doesn't matter that you don't fully trust the host.

Everyone else runs:

```sh
./hush -n yourname HOST          # e.g. ./hush -n alice 100.64.0.1
./hush -n yourname HOST:PORT     # or HOST PORT; [ipv6]:PORT for IPv6
```

Prefer a browser window? `web/hush-web` takes the same arguments, runs `hush` for you and
serves the chat on localhost (needs only Python 3):

```sh
./web/hush-web -n yourname HOST              # then open the link it prints
./web/hush-web --listen 8000 -n yourname HOST
```

The page only talks to the local `hush` process, so keys and encryption stay in the C client.
It listens on 127.0.0.1 only, and the link contains a random token that other websites can't
guess. Anyone with that link and access to your machine can read and send as you, so don't share it.

Your identity key is created on first run in `~/.local/share/hush/identity.key`.
Back it up. If you lose it, your friends will get a "key changed" warning.

## Commands

| | |
|---|---|
| `text` + Enter | send to everyone online |
| `/msg NAME TEXT` | private message |
| `/who` | who's online, with fingerprints and trust state |
| `/fp [NAME]` | your fingerprint, or someone else's |
| `/verify NAME` | mark NAME as verified after comparing fingerprints |
| `/trust NAME` | accept NAME's new key after it changed |
| `/quit`, Ctrl-C | leave |

Verify your friends once. On a call (or in person), each of you reads out
the fingerprint from `/fp`, checks it against what `/fp THEIRNAME` shows, and then runs
`/verify THEIRNAME`. After that, even a malicious server can't read your messages or
pose as your friends.

## How it works

- Each user has an Ed25519 identity keypair. To log in, you sign a random challenge from the server,
  and the server pins each name to the first key that registers it.
- Each message is encrypted separately for each recipient with libsodium's `crypto_box`
  (X25519 key agreement, XSalsa20-Poly1305) and a fresh random nonce.
  The server only ever sees `recipient name + ciphertext`.
- Inside the ciphertext: message kind (room/DM), a strictly increasing counter
  (so replayed messages are rejected), the sender's name (so the server can't bounce your own
  message back to you as someone else's), and the text.
- Key pinning (TOFU): your client remembers every friend's key in
  `~/.local/share/hush/known_peers`. If the server ever hands you a different key for
  them, the client warns you loudly and refuses to send to or accept from that key until you `/trust` it.
- Incoming text is stripped of terminal control sequences, so nobody can inject escape codes into your terminal.

## Limitations (read these)

This is a hobby project, not a professional security audit. Specifically:

- No forward secrecy. If someone records the encrypted traffic and later steals your
  `identity.key`, they can decrypt the recorded messages. (Signal fixes this with the
  Double Ratchet algorithm.)
- The server sees metadata: who is online, who messages whom, when, and roughly how long each message is.
  The connection itself isn't wrapped in TLS, so anyone on the network path sees that metadata too.
- Your identity key is stored unencrypted (file permission 0600). Anyone with access to your account can take it.
- No offline delivery or history: you only get messages sent while you're connected.
- A malicious server can drop messages or refuse to relay them. It can't read or forge them.
