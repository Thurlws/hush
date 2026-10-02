# The hush protocol

How clients and hushd talk. `src/proto.h` is the reference. This explains it with
more context. For what gets encrypted and how, see [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md).

## Transports

Terminal clients connect over TCP (port 7777 by default). Every frame is

```
u32 big-endian length | u8 type | payload
```

where the length covers the type byte and the payload, and is at most 65536.
A length of 0 or more than 65536 drops the connection.

Browsers use a WebSocket at `/ws` on the web port (8080 by default). Each binary
WebSocket message is one frame without the length: `u8 type | payload`. hushd only
accepts masked, unfragmented frames of up to 64 KB, and refuses the upgrade unless
the `Origin` header names the same host the page came from.

Both transports carry the same frames, so a browser and a terminal client in the
same chat can't tell each other apart.

Integers are big-endian. A name (or chat label) is `u8 length | bytes`, 1 to 24
characters of `A-Z a-z 0-9 _ . -`. Where a recipient is expected, length 0 means
the whole chat.

## Logging in

```
client                                 server
HELLO   name, public key, token, v1  ->
                                     <- CHALLENGE  32 random bytes
AUTH    signature over the challenge ->
                                     <- WELCOME    chat label, flags
                                     <- PEER       one per member of the chat
```

The token is derived from the chat key and identifies the chat (CRYPTOGRAPHY.md
has the details). The signature is Ed25519 over `hush-auth-v3` followed by the
challenge. The first time a name logs in, the server pins it to that public key,
and from then on a different key can't use the name.

Someone new to a chat gets `WAITING` instead of `WELCOME` and sees nothing until
an admin decides. Admins in the chat get a `PENDING` for them and answer with
`DECIDE`. If the answer is yes the waiting client gets `WELCOME` and carries on,
if it's no they get an error and the connection closes.

A HELLO whose token is 32 zero bytes asks for no chat. Only admins get through,
with `ADMIN` instead of `WELCOME`, and the only thing they can do then is send
`NEWCHAT`. This is how the home page's "Create your own" works.

A connection has 15 seconds to finish logging in, or 60 for the admin-only login.
People on the waitlist can stay connected as long as they like.

## Versions

The last byte of HELLO is the protocol version, currently 1. hushd accepts versions
`HUSH_PROTO_MIN` to `HUSH_PROTO` (0 to 1 right now) and refuses anything else with
an error that names both versions and says which side needs updating:

```
unsupported protocol version 9 (this server speaks 0 to 1), the server needs updating
```

A HELLO without the byte counts as version 0. Those are clients from before
versions existed. They're still accepted because nothing else on the wire changed.
The first incompatible change will raise both numbers, and from then on old
clients get that error instead of failing in some confusing way.

The version covers the frames. A few other things carry their own version and
change independently:

| What | Where | Current |
|---|---|---|
| Message plaintext layout | first byte of every plaintext | 3 |
| Signature contexts | `hush-auth-v3`, `hush-msg-v3` | v3 |
| Chat key derivation | BLAKE2b keys `hush-chat-*-v4` | v4 (24-character keys use v3) |
| Database schema | `PRAGMA user_version` in `hushd.db` | 2 |

## Frames

Client to server:

| Type | Name | Payload |
|---|---|---|
| 1 | HELLO | name, public key (32), token (32), version (u8) |
| 2 | AUTH | signature (64) |
| 3 | POST | recipient name (empty for the chat), message body |
| 4 | HISTORY | dir (u8), anchor message id (u64), limit (u16) |
| 5 | UPLOAD | flags (u8: 1 first, 2 last), data |
| 6 | FETCH | blob id (16) |
| 7 | DECIDE | approve (u8), name |
| 8 | NEWCHAT | chat label, token (32) of a key the client made |

Server to client:

| Type | Name | Payload |
|---|---|---|
| 10 | CHALLENGE | 32 random bytes |
| 11 | WELCOME | chat label, flags (u8: 1 means admin) |
| 12 | PEER | name, public key (32), flags (u8: 1 online, 2 just joined) |
| 13 | LEAVE | name |
| 14 | MSG | id (u64), server time in ms (u64), live (u8), sender, recipient, body |
| 15 | ERROR | UTF-8 text |
| 16 | HISTORY_END | dir (u8), more (u8) |
| 17 | UPLOADED | blob id (16) |
| 18 | BLOB | blob id (16), status (u8: 0 part, 1 last part, 2 missing), data |
| 19 | WAITING | chat label |
| 20 | PENDING | waiting (u8: 1 waiting, 0 decided), name, public key (32) |
| 21 | CREATED | chat label |
| 22 | ADMIN | nothing |

Any frame that doesn't fit the connection's state (a POST before logging in, a HELLO
after it) is a protocol violation and ends the connection.

As an example, alice saying hello over TCP is 76 bytes:

```
00 00 00 48   length 72: the type byte and 71 bytes of payload
01            HELLO
05 61 6c 69 63 65   "alice"
..32 bytes..  her Ed25519 public key
..32 bytes..  the login token
01            protocol version 1
```

## Messages

A POST carries a body the server can't read: a 24-byte nonce and the ciphertext
(CRYPTOGRAPHY.md has the plaintext layout). hushd checks the recipient is in the
chat, refuses bodies smaller than an empty signed message or bigger than the largest
one a real client builds (about 4.3 KB), stores it, and sends a `MSG` to everyone
concerned who is online, the sender included. Live messages have `live` set to 1.

`HISTORY` asks for stored messages. `dir` 0 means older than the anchor (anchor 0
means the newest), 1 means newer, and 2 means newer but only what you sent or what
was sent to you, which is what "My data" uses. The limit is at most 200. The server
answers with `MSG` frames (`live` 0), oldest first, then `HISTORY_END` saying whether
there's more. DMs only ever reach their sender and recipient, in history too.

### Delivery and ordering

Message ids are SQLite row ids, so they follow the order the server stored messages
in. A live `MSG` goes out once, to whoever is connected at that moment. Anyone
who wasn't connected gets it from history later. After a reconnect the web client
asks for everything newer than the last id it saw, and keeps paging while
`HISTORY_END` says there's more. Messages can therefore arrive twice (live, then in
a history page), and clients drop repeats using the random 16-byte id inside each
plaintext.

There's no queue of outgoing messages on the client. If the connection is down, a
message isn't sent and the client says so. There is no application-level heartbeat
either: WebSocket pings get a pong, and a dead TCP connection is noticed when the
next write fails.

## Images

An image goes up in pieces with `UPLOAD`: the first piece has flag 1, the last has
flag 2, and a single-piece upload has both. Clients send 48 KB pieces. The total is
at most 25 MB plus 40 bytes of nonce and tag, there's one upload per connection at a
time, and the server refuses uploads when it has less than 1 GB of disk free. When
the last piece is stored the server answers `UPLOADED` with a random blob id, and
the client posts a message that carries the id and the image's key.

`FETCH` asks for a blob by id. The server answers with `BLOB` frames, and only if
the blob was uploaded in the same chat. Otherwise the status is 2, "missing", the
same answer as for an id that doesn't exist. Up to 16 fetches can be queued per
connection.

## Errors and closing

`ERROR` carries a sentence meant for people, like `wrong key` or `only an admin can
do that`. Some errors are just information and the connection stays open. Others
(wrong key, protocol violations, malformed requests, sending too fast) end it: the
server sends the error, stops reading, shuts down its side once everything is out,
and waits up to 2 seconds for the client to hang up. Without that wait, a client
that was still sending would get a TCP reset and lose the error before reading it.
Frames that can't be parsed at all just drop the connection.

WebSocket close codes tell the browser what to do next:

| Code | Meaning | Browser does |
|---|---|---|
| 4000 | refused, with an ERROR just before | shows the error, doesn't retry |
| 1001 | the server is shutting down | reconnects with backoff if it was in a chat |
| 1000 | normal close | the same |

On SIGTERM terminal clients get `ERROR the server is shutting down` before the
connection closes.

## Limits

| What | Limit |
|---|---|
| Frame | 64 KB |
| Message body | about 4.3 KB (text up to 4000 bytes) |
| Image | 25 MB |
| History page | 200 messages |
| Messages, history requests, downloads and new chats | 60 at once, then 5 a second, per connection |
| Wrong chat keys | 5, then one a minute, per IP address |
| New connections and page loads | 30 at once, then one every 2 seconds, per IP address |
| Open connections | 16 per IP address |
| Uploaded bytes | 100 MB at once, then 1 MB a second, per IP address |
| Waitlist | 50 people per chat |

IPv6 addresses count per /64. Behind a reverse proxy started with `-x`, the limits
apply to the last address in `X-Forwarded-For`.
