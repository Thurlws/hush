# How hush is tested

```sh
make test          # unit tests, then the end-to-end suite
make asan test     # both under AddressSanitizer and UBSan
make analyze       # clang-tidy and gcc -fanalyzer
make fuzz          # libFuzzer, 60 seconds per target by default
make coverage      # line coverage of both test suites together
```

CI (`.github/workflows/ci.yml`) runs all four on every push, with gcc and clang
builds both treating warnings as errors. The numbers below are from Arch Linux on a
Ryzen 7 7800X3D with gcc 16 and clang 22.

## Unit tests

`tests/unit.c` covers the code that needs no network or database: framing, names,
chat key derivation, message encryption, parsing and signatures, image metadata,
JSON output, the HTTP parser and WebSocket frames. 142 checks, well under a second.

Chat key derivation is checked against values computed by `web/hush.js` (for the
Argon2id keys) and by Python's `hashlib` (for the old 24-character keys and
fingerprints). If the C and browser clients ever derived different keys from the
same chat key, they couldn't talk to each other, and this is where it would show.

Message tests build a message the way the client does, then break it in every way
that should matter: the wrong chat key, a flipped ciphertext or nonce byte, a
relabeled sender, edited text, a signature checked against someone else's key, a
message replayed into another chat, and a DM opened with the chat key or a third
person's key. Each has to fail.

## End-to-end

`test.sh` builds nothing. It starts real hushd processes on localhost and drives
terminal clients, the web client's protocol code under Node (`test-web.mjs`) and
the HTTP side with curl. 156 checks, about two minutes. Without Node the web parts
are skipped and say so.

What it covers, roughly in order:

- Logging in: wrong keys, old 24-character keys, keys typed in odd ways, protocol
  versions, the first admin, names already taken.
- Chats: messages, DMs across terminal and browser, history for newcomers without
  other people's DMs, offline DMs, images with their metadata stripped, "My data",
  `hushd export`.
- The waitlist: approving and denying from a client and from the command line,
  people waiting seeing nothing, denied people staying out.
- Key changes: when the server hands out a new key for someone, clients hide their
  messages and refuse to encrypt DMs to them, until `/trust`. Then `/verify`.
- What gets shown: escape codes and bidi overrides sent from a browser arrive in a
  terminal defused, and JPEG, PNG and WebP metadata is gone after sending.
- The web server: headers, path traversal, methods, Origin checks.
- Admin commands: `clear`, `revoke`, `forget`, old key formats, database migrations, and a
  backup of the running server, opened and exported again to compare with the original.
- Permissions the server checks itself, using raw frames a normal client wouldn't
  send: DECIDE and NEWCHAT from non-admins, posting from the waitlist, fetching an
  image from another chat, a message bigger than any client builds.
- Hostile input on a fresh server: a HELLO trickled one byte at a time, zero-length
  and oversized frames, frames out of order, unmasked, fragmented and 1 TB WebSocket
  frames, and bursts of random frames after logging in.
- Shutdown and crashes: SIGTERM tells clients and leaves no WAL behind, and a
  `kill -9` in the middle of an upload leaves an intact database, no partial upload
  after the restart, and the history from before.
- Rate limits, directly and behind a reverse proxy.

## Sanitizers

`make asan test` rebuilds everything with `-fsanitize=address,undefined` and runs both
suites. `test.sh` points every process's sanitizer output into a folder and fails if
anything lands there, which matters because the clients and servers it starts write
to files the suite deletes afterwards. With that in place, the whole suite runs clean.

## Fuzzing

`fuzz/` has a libFuzzer target for each piece of code that reads raw network bytes or
decrypted plaintext:

| Target | What it feeds | 10-minute run |
|---|---|---|
| `http` | `http_parse`, then serving and the WebSocket upgrade on whatever it accepts | 159 million inputs, 130 edges |
| `ws` | WebSocket frames, read in a loop the way the server does | 256 million inputs, 32 edges |
| `frame` | TCP frames and the names inside them | 257 million inputs, 49 edges |
| `msg` | a body through decryption, a plaintext through parsing, signatures, image parsing and JSON | 34 million inputs, 105 edges |

None crashed, leaked or hung. Seeds in `fuzz/seeds/` are real protocol examples, and
what the fuzzers learn goes in `fuzz/corpus/`, which isn't committed.

The server's message handlers aren't fuzzed directly, because they need a database
and connection state. The random-frames test in `test.sh` stands in for that.

## Coverage

`make coverage` builds with `--coverage`, runs both suites, and prints line coverage per
file. Every process the suites start (hushd, terminal clients, the unit tests) adds to
the same counts.

| File | Lines | Covered |
|---|---|---|
| `src/proto.c` | 148 | 98.7% |
| `src/msg.c` | 79 | 98.7% |
| `src/web.c` | 255 | 94.5% |
| `src/server.c` | 1565 | 84.0% |
| `src/client.c` | 1121 | 77.5% |
| total | 3168 | 83.6% |

Most of what's left in `client.c` is the interactive terminal: raw mode, the line
editor and the hidden key prompt, which a test feeding stdin through a pipe never
reaches. In `server.c` it's mostly errors from the disk and the database, and the code
that finds the installed web files. Looking at the first coverage report also found
that `/trust`, `/verify` and PNG and WebP metadata stripping had no tests, and writing
them turned up a real difference: the browser dropped Unicode bidi overrides from
messages but the terminal showed them, so a message could display backwards in one
client and not the other.

## Static analysis

`make analyze` runs clang-tidy with the bugprone, CERT and clang-analyzer checks, and
gcc's `-fanalyzer`, and fails on any finding. `.clang-tidy` lists the checks that are
off and why. Three lines carry a `NOLINT` for a false positive, each naming the check
and the reason.

Everything builds without warnings under `-Wall -Wextra -Wpedantic -Wconversion
-Wshadow -Wformat=2 -Wundef` with both compilers.

## What testing turned up

| Problem | Found by | Fix |
|---|---|---|
| A refused client that was still sending never saw the error: closing with unread input made the kernel reset the connection, and browsers dropped the error frame | the random-frames test | `6bd7d1a` |
| Message bodies had no upper bound, so a member could store 64 KB of junk per message, and a 200-message history page then exceeded the 4 MB a client may have queued, disconnecting anyone who opened the chat | reading the handlers | `1e6415a` |
| Messages skipped the low-disk check that uploads have | reading the handlers | `1e6415a` |
| `db_migrate()` would read `migrations[-1]` if reading the schema version failed | clang-tidy | `1aad7ad` |
| `hushd export` closed an image file twice when writing it failed | clang-tidy | `1aad7ad` |
| Three read loops called `fread` again after EOF or an error, and `/img` sent a partial image when reading failed | clang-tidy | `1aad7ad` |
| 16 implicit sign and float conversions, and a buffer in `handshake()` shadowing another | clang with `-Wconversion -Wshadow` | `153e01a` |
| The sanitizer build linked the unit tests without sanitizer flags | the first `make asan test` | `2826df8` |
| The terminal showed Unicode bidi overrides that the browser removes | writing tests for code that coverage showed untested | `ed58a8b` |

## What isn't covered

- The interactive parts: the terminal line editor and the browser UI in `app.js`.
  The screenshots in the README come from a scripted run of the real UI, but nothing
  checks it automatically.
- Running out of disk. The low-disk refusals exist but are hard to trigger in a test.
- Load. There's no benchmark yet, and the limits have only been exercised one
  client at a time.
- Other systems. hush is Linux only, and CI runs on Arch.
