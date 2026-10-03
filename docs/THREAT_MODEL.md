# Threat model

What hush tries to protect, from whom, what it assumes, and what it leaves alone.
The mechanisms are in [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) and
[PROTOCOL.md](PROTOCOL.md).

## What's worth protecting

- What people say: chat messages, private messages and images.
- That a message really comes from who it says, in the chat it says.
- The secret half of each person's identity key, and the chat keys.
- Who gets into a chat at all.
- The server staying up for the people who use it.

## Who might attack

| Attacker | Has |
|---|---|
| Someone on the network | can watch traffic, and change it if it isn't TLS |
| A stranger on the internet | the server's address, no chat key |
| A member | a chat key, and maybe a seat in the chat |
| An admin | the admin panel: who's connected from where, every chat's members, kicks, bans, deleting chats |
| The person running the server | everything the server stores and sends |
| Someone with the server's files | a copy of the disk or a backup |
| Someone with your device | your identity key and saved chat keys |
| A website you visit | your browser, while you're on their page |

## What hush assumes

- libsodium and libsodium.js are correct, and the operating system's random numbers
  are good.
- The devices people chat from aren't compromised.
- Browser users get the page over HTTPS from an honest server. The page does the
  encryption, so whoever serves the page can change it.
- Chat keys are passed around privately, the way you'd share a password.
- For the strongest guarantees, people compare fingerprints once over a channel the
  server doesn't control, like a call.

## What it guarantees, given that

- The server and the network never see message or image contents. They only handle
  ciphertext, and the server never has a key that decrypts anything.
- Nobody can forge a message from someone else, or relabel, move between chats or
  replay one without clients dropping it. Messages are signed by the sender's
  identity key over the chat id, the sender, the recipient, the time and a random id.
- Private messages can only be read by the two people in them, not by other members.
- If the server swaps someone's identity key, clients that saw the old key notice,
  warn and stop trusting it. Clients that verified fingerprints are protected even
  if the server lies from the start.
- Only people with the chat key can log in to a chat, and only an admin can let a
  new person in. The server enforces both: someone waiting gets nothing from the
  chat, not even who's in it.
- A new member gets the history from when they were let in, and an admin decides
  whether they see more. The server enforces that as well (see below for its limits).
- Being an admin doesn't open any chat. Admins can manage a chat from outside it,
  but reading it still takes its key.
- Strangers without a key can't do much beyond loading the web page. Logins, page
  loads, uploads and open connections are rate limited per address.

## What it doesn't

- Metadata. The server knows who is in which chat, who messages whom, when, and how
  big each message and image is. The terminal client's connection has no TLS, so the
  network sees that too. Admins see part of it: the session list shows everyone's
  name, chat and IP address, and since when they've been connected.
- A malicious server serving a malicious page. Browser users run the JavaScript the
  server sends. The terminal client doesn't have this problem.
- Forward secrecy. A chat key that leaks later still opens the whole stored history,
  and so does one person's identity key for their DMs.
- History the server didn't send. Everyone in a chat has the same key, so a member
  who gets the stored ciphertext some other way (a backup, or another member's copy)
  can read all of it, from before they joined too. The same goes for someone an
  admin removed: the server stops sending them anything, but only a new key
  (`hushd revoke`, then `newkey`) locks them out of the encryption.
- A compromised device. Identity and chat keys are stored unencrypted, protected only
  by file permissions and the browser profile.
- Availability against the server or a big attack. The server can drop, delay or
  reorder messages, and the rate limits won't stop a large botnet.
- Members being annoying. Someone with the key can post as much as the rate limits
  allow, register many names one after another (an identity key gets one session at
  a time), or send images built to make browsers struggle to decode them. WebSocket
  pings aren't rate limited either, though each one only gets a pong back.

## Walkthroughs

### Someone steals a backup of the server

They get `hushd-keys.txt` (one hash per
chat), the user and admin lists, and `hushd.db` and `blobs/` full of ciphertext. To
read a chat they have to find its key by guessing. Each guess is a full Argon2id run
with 128 MiB of memory, about 100 ms on a fast desktop, so the whole 40-bit space is
around 3,400 CPU-years. Chats with old 24-character keys have 120 bits and skip
Argon2id. Mitigation if it happens anyway: `hushd revoke` the chats and make new keys.

### Someone guesses keys by logging in

Each address gets 5 wrong keys, then one a
minute (IPv6 counts per /64). At that rate going through 2^40 keys takes about two
million years per address. The server logs every wrong key.

### The operator turns malicious

They can't read messages: they never get a chat
key, only a hash of a value derived from it. They can see the metadata above. They
can try to read DMs by announcing their own key for someone. Every client that saw
the real key warns about the change and refuses to encrypt to the new one, and that's
tested in `test.sh`. They can serve browsers a page that leaks messages, which is
the main reason to prefer the terminal client if you don't trust the server.

### A member wants to impersonate another member

The server pins each name to the
first identity key that used it, so they can't log in as that name. A message they
build with someone else's name fails the signature check, because they don't have
that person's secret key. Relabeling a real message (changing who it's from or to on
the server) fails the check that the plaintext matches the labels.

### A stranger tries to join without being approved

Having the key isn't enough:
newcomers land on the waitlist and get nothing from the chat until an admin approves
them. The waitlist protects the server, not the encryption, though. Someone with the
key and a copy of the server's files could decrypt the chat without ever being let in.

### Someone keeps coming back

An admin can kick a session, remove a member from a chat and ban an IP address.
Bans are the weakest of the three: a phone network or another Wi-Fi gives a new
address, and an IPv6 ban covers one /64. Every new identity has to get past the
waitlist, though, and a removed member goes back on it, so what decides who gets in
is still an admin approving them. Someone denied stays out until an admin changes
their mind. Loopback addresses can't be banned: behind a reverse proxy without `-x`,
everyone arrives from 127.0.0.1, and a ban would lock out the whole server.

### A client sends garbage

Frames over 64 KB, zero-length frames, unmasked or
fragmented WebSocket frames, frames that don't fit the connection's state and
messages bigger than any real client builds all end the connection. The parsers are
fuzzed and `test.sh` sends broken and random frames at a running server.
[TESTING.md](TESTING.md) has the details.

### Another website tries to use your browser

A page on another site can't open a
WebSocket to hushd as you, because the server checks `Origin`. It can't frame the
page, load its scripts into another origin, or read its storage, because of the
Content-Security-Policy and the browser's same-origin rules.

### Your laptop is stolen

The thief gets your identity key and, in the browser, the
keys of chats you saved. They can read those chats and post as you. What to do: an
admin can remove that identity from the chats in the admin panel straight away, which
stops the server sending it anything. To lock it out of the encryption too, `hushd
revoke` the chats and make new keys. Then `hushd forget` your name so you can register
a new identity.
