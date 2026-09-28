# hush

End-to-end encrypted group chat for you and your friends, in C. Chat in the browser or in the terminal.

- `hushd` is the server. It serves the web page, relays encrypted messages, and cannot read them.
  Only the person running it can create the keys that let people into a chat.
- The web page (`web/`) and the terminal client (`hush`) hold your keys and do the encryption.
  Both talk the same protocol, so browser and terminal users can chat together.

## Build

Needs a C compiler and [libsodium](https://libsodium.org):

```sh
sudo apt install build-essential pkg-config libsodium-dev     # Ubuntu/Debian
sudo dnf install gcc make pkgconf libsodium-devel             # Oracle Linux/Fedora (EPEL for libsodium)
sudo pacman -S base-devel libsodium                           # Arch

make
./test.sh           # optional: end-to-end tests on localhost
```

`hush` and `hushd` are build output, so they aren't in git. `make` creates them from `src/`.

## Quick start

```sh
./hushd newkey friends     # prints a key for a chat called "friends"
./hushd                    # web page on port 8080, terminal clients on port 7777
```

Open `http://SERVER-IP:8080`, enter the key and a name, and you're in. Give the key to your friends.

## Running it on a VPS

This is the setup for a small cloud server, e.g. an Oracle Cloud free VM. You get
`https://chat.example.com` with a real certificate, and hushd runs as a locked-down service.

1. **A domain name.** HTTPS needs one. Any domain works, or a free subdomain from e.g.
   [DuckDNS](https://www.duckdns.org). Point it at the VM's public IP.

2. **Open ports 80 and 443** (and 7777 if anyone uses the terminal client). On Oracle Cloud there are two firewalls:
   - In the web console: *Networking → Virtual cloud networks → your VCN → Security Lists → Add Ingress Rules*,
     source `0.0.0.0/0`, TCP, destination ports `80,443,7777`.
   - On the VM itself:
     ```sh
     # Ubuntu images (iptables)
     for p in 80 443 7777; do sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport $p -j ACCEPT; done
     sudo netfilter-persistent save
     # Oracle Linux images (firewalld)
     for p in 80 443 7777; do sudo firewall-cmd --permanent --add-port=$p/tcp; done; sudo firewall-cmd --reload
     ```
   Keep 8080 closed: only the reverse proxy on the VM itself should talk to it.

3. **Install hushd** as a service with its own user:
   ```sh
   git clone https://github.com/Thurlws/hush && cd hush
   make && sudo make install PREFIX=/usr/local
   sudo useradd --system --home-dir /var/lib/hush --create-home --shell /usr/sbin/nologin hush
   sudo chmod 700 /var/lib/hush
   sudo cp contrib/hushd.service /etc/systemd/system/
   sudo systemctl enable --now hushd
   ```

4. **HTTPS with [Caddy](https://caddyserver.com/docs/install)**, which gets and renews the certificate itself.
   Put this in `/etc/caddy/Caddyfile` and run `sudo systemctl reload caddy`:
   ```
   chat.example.com {
       reverse_proxy 127.0.0.1:8080
   }
   ```
   The service runs `hushd -x`, which makes it trust the `X-Forwarded-For` header from Caddy,
   so the rate limits apply to each visitor's real address.

5. **Create a chat key** and give it to your friends:
   ```sh
   sudo -u hush hushd -k /var/lib/hush/hushd-keys.txt newkey friends
   ```

Logs: `journalctl -u hushd -f`. To update: `git pull && make && sudo make install PREFIX=/usr/local && sudo systemctl restart hushd`.

## Managing chats

Each key opens one chat. Only whoever can run `hushd` on the server can create keys.

```sh
hushd newkey NAME     # new chat; prints its key once (the server keeps only a hash)
hushd keys            # list chats
hushd revoke NAME     # delete a key; everyone in that chat is disconnected
hushd forget USER     # free up a name, e.g. when a friend lost their browser data
```

A running server picks up these changes by itself. For the VPS setup above, run them as
`sudo -u hush hushd -k /var/lib/hush/hushd-keys.txt -u /var/lib/hush/hushd-users.txt ...`.

The first time someone joins with a name, the server ties that name to their identity key,
so nobody else can use it. A new browser or device has a new key, so it needs a new name
(or `hushd forget` the old one).

## Terminal client

```sh
./hush -n yourname HOST                 # asks for the chat key
./hush -n yourname -k KEY HOST:PORT     # or HOST PORT; [ipv6]:PORT; the key can also go in $HUSH_KEY
```

Prefer the prompt or `$HUSH_KEY` over `-k`, since other users on your machine can see command lines.
Your identity key is created on first run in `~/.local/share/hush/identity.key`.
Back it up. If you lose it, your friends will get a "key changed" warning.

## Commands

The same in the browser and the terminal:

| | |
|---|---|
| `text` + Enter | send to everyone in the chat |
| `/msg NAME TEXT` | private message |
| `/who` | who's here, with fingerprints and trust state |
| `/fp [NAME]` | your fingerprint, or someone else's |
| `/verify NAME` | mark NAME as verified after comparing fingerprints |
| `/trust NAME` | accept NAME's new key after it changed |
| `/quit` | leave (also the Leave button, or Ctrl-C in the terminal) |

Verify your friends once. On a call (or in person), each of you reads out
the fingerprint from `/fp`, checks it against what `/fp THEIRNAME` shows, and then runs
`/verify THEIRNAME`. After that, the server can't swap in its own key to read your messages
or pose as your friends without you getting a loud warning.

## How it works

- Each user has an Ed25519 identity keypair: in `identity.key` for the terminal client, and in the
  browser's local storage for the web page. It never leaves your machine.
- To log in, you send the chat key and sign a random challenge from the server. The server
  checks the chat key against its list of hashes, and pins each name to the first identity key that registers it.
- Each message is encrypted separately for each recipient with libsodium's `crypto_box`
  (X25519 key agreement, XSalsa20-Poly1305) and a fresh random nonce.
  The server only ever sees `recipient name + ciphertext`, and only relays within a chat.
- Inside the ciphertext: message kind (room/DM), a strictly increasing counter
  (so replayed messages are rejected), the sender's name (so the server can't bounce your own
  message back to you as someone else's), and the text.
- Key pinning (TOFU): your client remembers every friend's key. If the server ever hands you a
  different key for them, the client warns you loudly and refuses to send to or accept from that
  key until you `/trust` it.
- Browsers speak the same protocol over a WebSocket. The page uses
  [libsodium.js](https://github.com/jedisct1/libsodium.js), served by hushd itself (see `web/LIBSODIUM.txt`).

## Server hardening

- The chat key is 120 random bits. The server stores only a BLAKE2b hash of each key, in a `0600` file.
- Rate limits per IP address (per /64 for IPv6): new connections and page requests (burst of 30,
  then one every 2 seconds), open connections (16), wrong chat keys (5, then one a minute), and
  messages per connection. Over the limit, requests get `429` and logins get refused.
- Connections that don't finish their request within 10 seconds, or their login within 15, are dropped.
- The HTTP parser is strict and small: GET/HEAD only, 8 KB of headers, no control characters, no line folding,
  no duplicate `Host`. Only a fixed list of files is served, so request paths never touch the filesystem.
- There's no database, so there's nothing to inject SQL into. Names and chat labels are limited to
  `A-Z a-z 0-9 _ . -`, and all incoming text is shown as plain text, never parsed as HTML.
- Every page is sent with a strict Content-Security-Policy (only its own scripts, no inline code,
  can only connect back to this server, can't be framed), plus `nosniff`, `no-referrer` and friends.
- WebSocket connections from other websites are refused by checking the `Origin` header.
- `contrib/hushd.service` runs hushd as its own user, with no capabilities and a read-only view of
  the system apart from `/var/lib/hush`.
- `./test.sh` covers the above; the parsers have also been fuzzed with libFuzzer under ASan/UBSan.

## Limitations (read these)

This is a hobby project, not a professional security audit. Specifically:

- **The web page comes from the server.** If someone takes over your server, they can change the page to
  leak messages from browser users. That's true of any web-based encrypted chat. The terminal client
  doesn't have this problem, and fingerprint checks still catch key swaps.
- Use HTTPS. Over plain HTTP, anyone on the network path could change the page on its way to your friends.
- Anyone who has a chat key can join that chat. If a key leaks, `hushd revoke` it and make a new one.
- No forward secrecy. If someone records the encrypted traffic and later steals your identity key,
  they can decrypt the recorded messages. (Signal fixes this with the Double Ratchet algorithm.)
- The server sees metadata: who is in which chat, who messages whom, when, and roughly how long each message is.
  The terminal client's connection isn't wrapped in TLS, so anyone on the network path sees that metadata too.
- Identity keys are stored unencrypted (file permission 0600, or the browser's storage). Anyone with
  access to your account or browser profile can take them.
- No offline delivery or history: you only get messages sent while you're connected.
- A malicious server can drop messages or refuse to relay them. It can't read or forge them
  without you noticing a key change.
