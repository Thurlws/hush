# hush

End-to-end encrypted group chat for you and your friends, in C. Chat in the browser or in the terminal,
with history, private messages and images. New people wait on a waitlist until you let them in.

- `hushd` is the server. It serves the web page and stores and passes on encrypted messages and
  images, which it cannot read. Only the person running it, and the admins they pick, can create the keys
  that let people into a chat.
- The web page (`web/`) and the terminal client (`hush`) hold your keys and do the encryption.
  Both talk the same protocol, so browser and terminal users can chat together.

## Build

Needs a C compiler, [libsodium](https://libsodium.org) and SQLite:

```sh
sudo apt install build-essential pkg-config libsodium-dev libsqlite3-dev        # Ubuntu/Debian
sudo dnf install gcc make pkgconf libsodium-devel sqlite-devel                   # Oracle Linux/Fedora (EPEL for libsodium)
sudo pacman -S base-devel libsodium sqlite                                       # Arch

make
./test.sh           # optional: end-to-end tests on localhost
```

## Quick start

```sh
./hushd newkey friends     # prints a key for a chat called "friends"
./hushd                    # web page on port 8080, terminal clients on port 7777
```

Open `http://SERVER-IP:8080`. The login page shows your fingerprint. Make yourself admin with it,
then enter the key and a name:

```sh
./hushd admin "6937 b1d5 6e73 e529 69b1 ba58 820e f284"     # your fingerprint from the login page
```

Give the key to your friends. When they join, they wait until you approve them in the chat.

## Running it on a VPS

This is the setup for a small cloud server, e.g. an Oracle Cloud free VM. You get
`https://chat.example.com` with a real certificate, and hushd runs as a locked-down service.

1. **A domain name.** HTTPS needs one. Any domain works, or a free subdomain from e.g.
   [DuckDNS](https://www.duckdns.org). Point it at the VM's public IP.

2. **Open ports 80 and 443** (and 7777 if anyone uses the terminal client). On Oracle Cloud there are two firewalls:
   - In the web console: *Networking → Virtual cloud networks → your VCN → Security Lists → Add Ingress Rules*,
     source `0.0.0.0/0`, TCP, destination ports `80,443,7777`.
   - On the VM itself. The rules have to come before the image's catch-all REJECT rule, so insert them at the top:
     ```sh
     # Ubuntu images (iptables)
     for p in 80 443 7777; do sudo iptables -I INPUT 1 -p tcp --dport $p -m state --state NEW -j ACCEPT; done
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
   Put this in `/etc/caddy/Caddyfile`, with your own domain, and run `sudo systemctl reload caddy`:
   ```
   chat.example.com {
       reverse_proxy 127.0.0.1:8080
   }
   ```
   The service runs `hushd -x`, which makes it trust the `X-Forwarded-For` header from Caddy,
   so the rate limits apply to each visitor's real address.

5. **Create a chat key and make yourself admin.** Open your site; the login page shows your fingerprint.
   ```sh
   sudo -u hush hushd -C /var/lib/hush newkey friends
   sudo -u hush hushd -C /var/lib/hush admin "YOUR FINGERPRINT"
   ```
   Join with the key, then give it to your friends. Each of them waits until you approve them.

Logs: `journalctl -u hushd -f`. Everything the server keeps is in `/var/lib/hush`; back that up.

To update: `git pull && make && sudo make install PREFIX=/usr/local && sudo systemctl restart hushd`.

### Upgrading from the version without history

Chat keys work differently now, so old keys stop working. After updating (install `libsqlite3-dev`
first), make each chat a new key and send it to your friends again:

```sh
sudo -u hush hushd -C /var/lib/hush keys             # old keys are marked as old
sudo -u hush hushd -C /var/lib/hush revoke friends
sudo -u hush hushd -C /var/lib/hush newkey friends
sudo -u hush hushd -C /var/lib/hush admin "YOUR FINGERPRINT"
```

Names and fingerprints stay the same. People who were already in a chat don't have to be approved again.

## Managing chats

Each key opens one chat, and looks like `k3x7-9fqa`. Admins create chats on the home page:
**+ Add session**, then **Create your own** (or `/newchat NAME` in the terminal). The key is made on
their device. The server only gets a login token derived from it, and stores just a hash of that.
On the server:

```sh
hushd newkey NAME     # new chat; prints its key once (the server keeps only a hash)
hushd keys            # list chats, with how many messages and images each one stores
hushd clear NAME      # delete a chat's messages and images; the key keeps working
hushd revoke NAME     # delete a chat: its key, messages and images; everyone in it is disconnected
hushd forget USER     # free up a name, e.g. when a friend lost their browser data
```

A running server picks up these changes by itself. Add `-C DIR` to work on the files in DIR;
for the VPS setup above that's `sudo -u hush hushd -C /var/lib/hush ...`.

### Admins and the waitlist

Admins are identity keys, not names, so nobody becomes admin by picking your name. Everyone's
fingerprint is on their login page, and in `/fp`.

```sh
hushd admin "FINGERPRINT"     # that key is admin in every chat, and never waits
hushd unadmin "FINGERPRINT"
hushd admins                  # list them
```

The first time someone joins a chat, they land on a waiting screen and see nothing of the chat.
Admins in the chat get a request with the person's name and fingerprint, and **Approve** / **Deny**
buttons (in the terminal: `/approve NAME`, `/deny NAME`, `/waiting`). Check the fingerprint with them
before approving, e.g. over a call. Denied people can't try again. Without being online:

```sh
hushd pending                 # who's waiting for which chat
hushd approve CHAT NAME       # they get in within a second if they're waiting right now
hushd deny CHAT NAME
```

### Getting the data out

- Anyone can use the **My data** button to download a zip of everything they sent in the chat and
  every DM sent to them, with their images, decrypted in the browser. In the terminal, `/mydata`
  saves the same to a folder in `~/Downloads`.
- The operator can run `hushd export CHAT DIR`. It asks for the chat's key and decrypts the whole
  chat into `DIR`: `messages.txt` (readable), `messages.json` (with signature checks) and `images/`.
  DMs can't be opened with the chat key, so they're listed without their contents. The folder is the
  chat in plain form: copy it off the server and delete it there.

Messages and images are kept until you `clear` or `revoke` the chat. Uploads are refused
while the disk has less than 1 GB free.

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

| | |
|---|---|
| `text` + Enter | send to everyone in the chat |
| `/msg NAME TEXT` | private message; they get it even if they're offline |
| `/who` | who's in the chat, with fingerprints and trust state |
| `/fp [NAME]` | your fingerprint, or someone else's |
| `/verify NAME` | mark NAME as verified after comparing fingerprints |
| `/trust NAME` | accept NAME's new key after it changed |
| `/quit` | leave (also the Leave button, or Ctrl-C in the terminal) |
| `/waiting`, `/approve NAME`, `/deny NAME` | admins: the waitlist |
| `/newchat NAME` | admins: create a chat and get its key (in the page: + Add session, Create your own) |

In the browser, chats you've joined are saved on the login page: click one to rejoin, or
**+ Add session** to join another with its key. Send an image with the **+** button or by pasting
it; whatever is typed in the box goes along as its caption. Click an image to see it full size and
save it. **Load older messages** at the top goes back in time.

In the terminal: `/img FILE [caption]` sends an image (jpeg, png, gif or webp, up to 25 MB),
`/save N` saves image N to `~/Downloads`, `/more` shows older messages, and `/mydata` saves your data.

Verify your friends once. On a call (or in person), each of you reads out
the fingerprint from `/fp`, checks it against what `/fp THEIRNAME` shows, and then runs
`/verify THEIRNAME`. After that, the server can't swap in its own key to read your DMs
or pose as your friends without you getting a loud warning.

## How it works

- Your client turns the chat key into two unrelated values: a login token, which is all the server
  ever sees (it stores only a hash of it), and the chat's encryption key, which never leaves the clients.
- Each user has an Ed25519 identity keypair: in `identity.key` for the terminal client, and in the
  browser's local storage for the web page. It never leaves your device. To log in, you sign a random
  challenge from the server, and the server ties each name to the first identity key that registers it.
- Chat messages are encrypted with the chat's key (XChaCha20-Poly1305), so everyone in the chat,
  including people who join later, can read its history. DMs are encrypted for just the two people
  involved with `crypto_box` (X25519, XSalsa20-Poly1305).
- Every message is signed by its sender's identity key. The signature covers the chat, the sender, the
  recipient, the time and a random ID, so nobody (members or server) can forge, relabel, move or
  replay a message without it being rejected.
- Images get their own random key. The encrypted image is uploaded, and the message carries the key.
  Before sending, the browser redraws photos (and the terminal client strips their metadata blocks),
  which removes hidden data like the GPS position phones store in them.
- The server keeps messages in SQLite and images as files, all encrypted. It knows who sent what to
  which chat or person, and when, but not what it says.
- The waitlist is enforced by the server: it sends people nothing from a chat until they're approved.
- Key pinning (TOFU): your client remembers every friend's key. If the server ever hands you a
  different key for them, the client warns you loudly and refuses to show their messages or send
  them DMs until you `/trust` it.
- Browsers speak the same protocol over a WebSocket. The page uses
  [libsodium.js](https://github.com/jedisct1/libsodium.js), served by hushd itself (see `web/LIBSODIUM.txt`).

## Server hardening

- A chat key is 40 random bits, stretched with Argon2id (128 MB, 3 passes) before anything is derived
  from it, so every guess costs real time and memory. The server stores only a hash of the login token,
  in a `0600` file. Guessing keys by logging in is capped by the rate limits below.
- Rate limits per IP address (per /64 for IPv6): new connections and page requests (burst of 30,
  then one every 2 seconds), open connections (16), wrong chat keys (5, then one a minute) and
  uploaded bytes (100 MB, then 1 MB a second), plus messages and requests per connection.
  Over the limit, requests get `429` and logins get refused.
- Connections that don't finish their request within 10 seconds, or their login within 15, are dropped.
- The HTTP parser is strict and small: GET/HEAD only, 8 KB of headers, no control characters, no line folding,
  no duplicate `Host`. Only a fixed list of files is served, so request paths never touch the filesystem;
  images only travel over the logged-in connection, and only to people in the same chat.
- Every database query is a prepared statement with bound parameters, so nothing a client sends can
  change a query (no SQL injection). Names and chat labels are limited to `A-Z a-z 0-9 _ . -`, and all
  incoming text is shown as plain text, never parsed as HTML.
- Every page is sent with a strict Content-Security-Policy (only its own scripts, no inline code,
  images only from decrypted data, can only connect back to this server, can't be framed),
  plus `nosniff`, `no-referrer` and friends. Only jpeg, png, gif and webp images are shown.
- WebSocket connections from other websites are refused by checking the `Origin` header.
- `contrib/hushd.service` runs hushd as its own user, with no capabilities and a read-only view of
  the system apart from `/var/lib/hush`.
- `./test.sh` covers the above. The HTTP and WebSocket parsers have been fuzzed with libFuzzer, and the
  logged-in protocol with random messages, under ASan/UBSan.

## Limitations (read these)

This is a hobby project and hasn't had a professional security audit.

- **The web page comes from the server.** If someone takes over your server, they can change the page to
  leak messages from browser users. That's true of any web-based encrypted chat. The terminal client
  doesn't have this problem, and fingerprint checks still catch key swaps.
- Use HTTPS. Over plain HTTP, anyone on the network path could change the page on its way to your friends.
- Chat keys are short so they're easy to share. Guessing one by logging in would take years at the
  rate limits, but someone who steals the server's files can try keys offline; Argon2id makes that
  cost thousands of CPU-years per chat, not seconds. Keys made before keys got shorter (24 characters)
  are much stronger and keep working.
- **Anyone with a chat key can read that chat's whole history**, including what was said before they
  joined. If a key leaks, `hushd revoke` it (which deletes the history) and make a new one.
- The waitlist keeps people out of the server, not out of the encryption: someone who has the chat key
  and also gets a copy of the server's files could read the chat without ever being approved.
- History is kept forever unless you `clear` it, and there's no forward secrecy: whoever gets both a copy
  of the server's files and the chat key (or, for DMs, one side's identity key) can read everything stored.
- Members can post junk the server can't tell apart from real messages, since it can't read them.
  Everyone else's client drops it with a warning.
- The server sees metadata: who is in which chat, who messages whom, when, how long each message is,
  and how big each image is. The terminal client's connection isn't wrapped in TLS, so anyone on the
  network path sees that metadata too.
- Identity keys, and in the browser the keys of saved chats, are stored unencrypted (file permission 0600,
  or the browser's storage). Anyone with access to your account or browser profile can take them.
  A new browser or device is a new identity.
- A malicious server can drop, hide or reorder messages. It can't read or forge them without you
  noticing a key change.
