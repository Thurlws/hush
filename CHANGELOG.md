# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/), and version numbers
follow [semantic versioning](https://semver.org/). Before 1.0 a minor release can include
incompatible changes, and the notes will say so.

## Unreleased

Protocol version 2 and database schema 3. The database upgrades itself. Old terminal clients
still work with the new server, but the new terminal client needs the new server.

### Added

- An admin panel in the browser, in the chat (**Admin**) and on the login page (**Manage
  server**): who's connected and from where, each chat's members, banned addresses, and
  buttons to kick, remove, ban, share history, and rename, clear or delete a chat. The
  terminal client has the same as commands.
- IP bans, kept in `hushd-bans.txt`, with `hushd ban`, `unban` and `bans`. IPv6 is banned per
  /64, and loopback can't be banned.
- `-L N` limits chat sessions per address, and an identity key gets one session at a time.
- `hushd share CHAT USER [DAYS]`, `/share` and `/approve NAME [DAYS|all]`.

### Changed

- New members see the history from when they were let in. An admin can share the last day,
  7 or 30 days, or all of it, when approving them or later. People who were already in a
  chat keep seeing all of it, and admins see everything.
- The web client keeps join and leave lines, and key warnings, across reloads and rejoins.
- `hushd` commands no longer create an empty database in a folder hushd hasn't run in.
  `hushd keys` says which folder it read.
- The admin-only login stays open instead of closing after 60 seconds.

## 0.1.0 (2026-10-03)

The first release: `hushd`, the terminal client `hush`, and the web client hushd serves.

### Added

- Group chats you join with a short key like `k3x7-9fqa`, stretched with Argon2id. The
  server stores only a hash of a token derived from it.
- Chat history for everyone with the key, private messages between two people, and
  images up to 25 MB with location and other metadata removed before sending.
- Ed25519 identities. Every message is signed, each person's key is pinned the first time
  it's seen, and `/verify` and `/trust` handle fingerprint checks and changed keys.
- A waitlist: newcomers wait until an admin lets them in. Admins are identity keys listed
  by fingerprint, so nobody becomes one by picking a name.
- Creating chats from the web page or with `/newchat`, and saved chats on the login page.
- "My data" and `/mydata` to download what you sent, and `hushd export` for the operator
  to decrypt a whole chat with its key.
- `hushd backup DIR`, safe while the server runs, with restore steps in
  docs/DEPLOYMENT.md.
- A protocol version at the end of the login handshake. Clients from before it count as
  version 0 and still work.
- Database schema migrations, a clean shutdown on SIGTERM and SIGINT, `/health` on the
  web port, and `-V` on both programs.
- A systemd unit, and a Dockerfile with a compose file.
- Docs: the protocol, the cryptography, a threat model, testing, a benchmark, and
  deployment.

### Fixed

- A client refused while it was still sending lost the error message to a TCP reset, so
  a rate-limited browser reconnected instead of saying why.
- Small messages could wait about 40 ms for the other side's delayed ACK, because
  neither side set `TCP_NODELAY`.
- `hushd export` closed an image file twice when writing it failed.
- The schema upgrade could read before the start of its list if SQLite failed to report
  the current version.

### Security

- Message bodies are capped at the size a real client builds. Before, a member could
  store 64 KB of junk per message and make a chat's history too big for anyone to load.
- Messages are refused when the disk has less than 1 GB free, like uploads already were.
- The terminal client removes Unicode bidi overrides from messages, as the browser
  already did, so a message can't display backwards in one client and not the other.
