#!/usr/bin/env bash
# End-to-end tests on localhost: a server, scripted terminal clients, the web
# client's protocol code under Node (if installed), and the HTTP side with
# curl. Run from the repo root after `make`.
set -u
cd "$(dirname "$0")"
T=$(mktemp -d)
PORT=${PORT:-17777}
WPORT=$((PORT + 1))
fail=0
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
# Sanitizer builds (make asan test) report here, checked at the end before $T goes away
mkdir -p "$T/san"
export ASAN_OPTIONS="log_path=$T/san/asan:${ASAN_OPTIONS:-}"
export UBSAN_OPTIONS="log_path=$T/san/ubsan:print_stacktrace=1:${UBSAN_OPTIONS:-}"

check() { # file pattern description
    if grep -qaF -- "$2" "$1"; then echo "ok   - $3"; else echo "FAIL - $3"; echo "---- $1:"; cat "$1"; fail=1; fi
}
absent() { # file pattern description
    if grep -qaF -- "$2" "$1"; then echo "FAIL - $3"; echo "---- $1:"; cat "$1"; fail=1; else echo "ok   - $3"; fi
}
server() { # dir [extra options]: start hushd with its files in dir, and wait until it listens
    local dir=$1 before
    shift
    mkdir -p "$dir"
    before=$(grep -c "terminal clients on port" "$T/server.log" 2>/dev/null)
    ./hushd -C "$dir" -p "$PORT" -w "$WPORT" -d "$PWD/web" "$@" 2>>"$T/server.log" &
    srv=$!
    # it logs this once both ports are listening. Probing the port would use up rate limit tokens
    for _ in $(seq 200); do
        [ "$(grep -c "terminal clients on port" "$T/server.log")" -gt "${before:-0}" ] && return
        sleep 0.05
    done
}
admin() { # hushd admin command in the current server's dir
    ./hushd -C "$S" "$@"
}
client() { # name datadir [key]
    HOME="$T/home" XDG_DATA_HOME="$T/$2" ./hush -n "$1" -k "${3:-$K1}" 127.0.0.1 "$PORT"
}
web() { # name [key]
    node test-web.mjs "$1" "${2:-$K1}" "ws://127.0.0.1:$WPORT/ws" "http://127.0.0.1:$WPORT" "$T/web-$1.id"
}
newkey() { # label -> prints the key
    admin newkey "$1" | sed -n 's/^    \([0-9a-z-]*\)$/\1/p'
}
code() { # curl args... -> HTTP status
    curl -s -o /dev/null -w "%{http_code}" "$@"
}
fingerprint() { # identity file (terminal: binary, web: hex) -> fingerprint
    python3 - "$1" <<'EOF'
import hashlib, sys
d = open(sys.argv[1], "rb").read()
sk = bytes.fromhex(d.decode()) if len(d) == 128 else d
print(hashlib.blake2b(sk[32:], digest_size=16).hexdigest())
EOF
}
trusted() { # datadir: give a terminal identity admin rights, so it skips the waitlist
    HOME="$T/home" XDG_DATA_HOME="$T/$1" ./hush -n x -k "$K1" 127.0.0.1 1 >/dev/null 2>&1 # creates the identity
    admin admin "$(fingerprint "$T/$1/hush/identity.key")" >/dev/null
}

# A JPEG whose EXIF block holds a (fake) GPS position.
mkdir -p "$T/home/Downloads"
python3 - "$T/photo.jpg" <<'EOF'
import struct, sys
exif = b"Exif\0\0" + b"GPS-51.5007N-0.1246W" * 4
seg = lambda m, d: b"\xff" + bytes([m]) + struct.pack(">H", len(d) + 2) + d
sof = struct.pack(">BHHB", 8, 480, 640, 1) + b"\x01\x11\x00"
open(sys.argv[1], "wb").write(b"\xff\xd8" + seg(0xE1, exif) + seg(0xDB, bytes(65)) + seg(0xC0, sof) +
                              b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + b"\x12\x34" * 500 + b"\xff\xd9")
EOF

S="$T/s1"
mkdir -p "$S"
K1=$(newkey main)
K2=$(newkey other)
./hush -V >"$T/version.out"; ./hushd -V >>"$T/version.out"
check "$T/version.out" "hush 0.1.0" "hush -V prints the version"
check "$T/version.out" "hushd 0.1.0" "hushd -V too"
[ -n "$K1" ] && [ -n "$K2" ] && echo "ok   - hushd newkey prints a key" || { echo "FAIL - hushd newkey"; fail=1; }
[[ $K1 =~ ^[0-9a-z]{4}-[0-9a-z]{4}$ ]] && echo "ok   - keys look like xxxx-xxxx" || { echo "FAIL - key format: $K1"; fail=1; }
# A key made before keys got shorter (24 characters, no Argon2id) must keep working.
KOLD=0123-4567-89ab-cdef-ghjk-mnpq
python3 - "$S/hushd-keys.txt" <<'EOF'
import hashlib, sys
token = hashlib.blake2b(b"0123456789abcdefghjkmnpq", digest_size=32, key=b"hush-chat-login-v3").digest()
verifier = hashlib.blake2b(token, digest_size=32, key=b"hush-chat-verify-v3").hexdigest()
open(sys.argv[1], "a").write(f"3 {verifier} oldstyle\n")
EOF
absent "$S/hushd-keys.txt" "$K1" "the keys file holds no plaintext keys"
admin keys >"$T/keys-nodb.out"
admin pending >>"$T/keys-nodb.out" 2>&1
check "$T/keys-nodb.out" "nothing is stored here yet" "hushd keys says when hushd hasn't run in its folder..."
check "$T/keys-nodb.out" "there's no hushd.db in $S" "...and so do the other commands"
[ ! -e "$S/hushd.db" ] && echo "ok   - ...without creating a database there" ||
    { echo "FAIL - a hushd command created a database"; fail=1; }

server "$S"

# Protocol versions: a HELLO without the version byte (old clients) still gets in, a newer
# version is refused with a reason. The zero token is the admin login, so no wrong-key strikes.
python3 - "$PORT" >"$T/proto.out" <<'EOF'
import socket, struct, sys
def hello(tag, extra):
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
    p = bytes([5]) + b"probe" + bytes(32) + bytes(32) + extra
    s.sendall(struct.pack(">IB", len(p) + 1, 1) + p)
    hdr = b""
    while len(hdr) < 5:
        hdr += s.recv(5 - len(hdr))
    n, t = struct.unpack(">IB", hdr)
    body = b""
    while len(body) < n - 1:
        body += s.recv(n - 1 - len(body))
    print(tag, "CHALLENGE" if t == 10 else f"type {t}", body.decode(errors="replace") if t == 15 else "")
    s.close()
hello("v0", b"")
hello("v1", b"\x01")
hello("v9", b"\x09")
EOF
check "$T/proto.out" "v0 CHALLENGE" "a HELLO without a version (old clients) still works"
check "$T/proto.out" "v1 CHALLENGE" "the current protocol version works"
check "$T/proto.out" "v9 type 15 unsupported protocol version 9 (this server speaks 0 to 1), the server needs updating" \
    "a newer protocol version is refused with a reason"

# The first person in, before there's an admin: they wait, until the operator
# makes their key an admin from the command line.
(sleep 3) | client alice a >"$T/alice0.out" 2>&1 &
a=$!
sleep 1
check "$T/alice0.out" "on the waitlist" "without an admin, even the first person waits"
admin admin "$(sed -n 's/.*fingerprint, \(.*\), so.*/\1/p' "$T/alice0.out")" >"$T/admin.out"
check "$T/admin.out" "now an admin" "hushd admin takes a fingerprint as shown to users"
wait $a
check "$T/alice0.out" "you're an admin" "...and lets them in as an admin, without a restart"
admin admins >"$T/admins.out"
check "$T/admins.out" "alice" "hushd admins lists admins by fingerprint and name"
for who in b c d e; do trusted $who; done

(sleep 1; echo "hello from alice"; sleep 1; echo "/msg bob just for you"; sleep 2) | client alice a >"$T/alice.out" 2>&1 &
a=$!
(sleep 1.5; echo "hi alice"; sleep 1; echo "/who"; sleep 1.5) | client bob b >"$T/bob.out" 2>&1 &
b=$!
(sleep 1.2; echo "anyone?"; sleep 1; echo "/msg alice sneaking in"; sleep 2) | client carol c "$K2" >"$T/carol.out" 2>&1 &
c=$!
wait $a $b $c

check  "$T/bob.out"    "alice: hello from alice"  "bob receives alice's message"
check  "$T/bob.out"    "[dm] alice: just for you" "bob receives alice's DM"
check  "$T/alice.out"  "bob: hi alice"            "alice receives bob's message"
check  "$T/alice.out"  "First time seeing them"   "alice pins bob's key on first sight"
check  "$T/bob.out"    "unverified"               "/who shows trust state"
check  "$T/alice.out"  "chat: main"               "clients are told which chat they're in"
absent "$T/carol.out"  "hello from alice"         "people in another chat don't see messages"
absent "$T/alice.out"  "carol"                    "people in another chat don't see each other"
check  "$T/carol.out"  "there is no alice in this chat" "no DMs across chats"

sleep 1 | client alice a "$KOLD" >"$T/alice-old.out" 2>&1
check "$T/alice-old.out" "chat: oldstyle" "24-character keys from before still work"

# An admin creates a chat from the terminal and its key works right away.
(sleep 0.5; echo "/newchat club"; sleep 1) | client alice a >"$T/alice-new.out" 2>&1
KC=$(grep -ao 'Its key: [0-9a-z-]*' "$T/alice-new.out" | cut -d' ' -f3)
check "$T/alice-new.out" "Created the chat \"club\"" "/newchat creates a chat"
sleep 1 | client bob b "$KC" >"$T/bob-club.out" 2>&1
check "$T/bob-club.out" "chat: club" "...and its key lets people in"
absent "$S/hushd-keys.txt" "$KC" "...and the server never got the key"
(sleep 0.5; echo "/newchat club2"; sleep 1) | client dave d >/dev/null 2>&1
admin keys >"$T/keys-club.out"
check  "$T/keys-club.out" "club" "hushd keys lists chats made in a client"

# History: someone who wasn't there gets the chat, but not other people's DMs.
sleep 2 | client dave d >"$T/dave.out" 2>&1
check  "$T/dave.out" "alice: hello from alice" "a newcomer sees the chat's history"
check  "$T/dave.out" "bob: hi alice"           "...all of it"
absent "$T/dave.out" "just for you"            "...but not DMs between others"

# The waitlist: amy is let in from the chat, zed is turned away, cli from the command line.
(sleep 2; echo "/waiting"; sleep 0.5; echo "/approve amy"; sleep 1.5; echo "/deny zed"; sleep 2) | client alice a >"$T/alice-wl.out" 2>&1 &
a=$!
sleep 0.5
(sleep 4; echo "/approve zed"; echo "hi, amy here"; sleep 1) | client amy am >"$T/amy.out" 2>&1 &
m=$!
sleep 0.3
(sleep 4) | client zed z >"$T/zed.out" 2>&1 &
z=$!
wait $a $m $z
check  "$T/alice-wl.out" "amy wants to join, with fingerprint" "admins see who wants to join, with their fingerprint"
check  "$T/alice-wl.out" "zed is waiting"                      "/waiting lists the waitlist"
check  "$T/amy.out"      "on the waitlist"                     "newcomers wait for approval"
check  "$T/amy.out"      "alice: hello from alice"             "once approved, they get the history"
check  "$T/amy.out"      "only an admin can do that"           "people who aren't admins can't approve anyone"
check  "$T/zed.out"      "didn't let you into this chat"       "a denied person is turned away"
absent "$T/zed.out"      "hello from alice"                    "people waiting see nothing of the chat"
sleep 1 | client zed z >"$T/zed2.out" 2>&1
check  "$T/zed2.out"     "didn't let you into this chat"       "...and stays turned away"
(sleep 3) | client cli cl >"$T/cli.out" 2>&1 &
c=$!
sleep 1
admin pending >"$T/pending.out"
check "$T/pending.out" "cli" "hushd pending lists who's waiting"
admin approve main cli >/dev/null
wait $c
check "$T/cli.out" "chat: main" "hushd approve lets someone in within a second"

# Offline delivery: a DM to someone who isn't connected waits for them.
(sleep 0.5; echo "/msg alice while you were out"; sleep 1) | client bob b >/dev/null 2>&1
sleep 2 | client alice a >"$T/alice-back.out" 2>&1
check "$T/alice-back.out" "[dm] bob: while you were out" "DMs sent while offline arrive later"

# Images, terminal to terminal.
(sleep 0.5; echo "/img $T/photo.jpg the view"; sleep 2) | client alice a >"$T/alice-img.out" 2>&1
check "$T/alice-img.out" "[image 640x480" "an image is sent"
id=$(grep -ao '/save [0-9]*' "$T/alice-img.out" | head -1 | cut -d' ' -f2)
(sleep 1; echo "/save $id"; sleep 2) | client bob b >"$T/bob-save.out" 2>&1
check  "$T/bob-save.out" "saved $T/home/Downloads/hush-$id.jpg" "and saved by someone else"
check  "$T/bob-save.out" "the view" "with its caption"
absent "$T/home/Downloads/hush-$id.jpg" "GPS" "photo location data is stripped before sending"
cmp -s <(tail -c 1004 "$T/photo.jpg") <(tail -c 1004 "$T/home/Downloads/hush-$id.jpg") &&
    echo "ok   - the picture itself is unchanged" || { echo "FAIL - image data changed"; fail=1; }
# PNG text chunks and WebP EXIF go too.
python3 - "$T/photo.png" "$T/photo.webp" <<'EOF'
import struct, sys, zlib
def chunk(t, d):
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
rows = b"\0" + b"\xff\x00\x00" * 2 + b"\0" + b"\x00\xff\x00" * 2
open(sys.argv[1], "wb").write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)) +
                              chunk(b"tEXt", b"Location\0GPS-51.5007N") + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))
def riff(t, d):
    return t + struct.pack("<I", len(d)) + d + (b"\0" if len(d) % 2 else b"")
body = b"WEBP" + riff(b"VP8X", bytes([0x08, 0, 0, 0, 1, 0, 0, 1, 0, 0])) + riff(b"VP8L", b"\x2f\x01\x00\x00\x00") + riff(b"EXIF", b"GPS-51.5007N")
open(sys.argv[2], "wb").write(b"RIFF" + struct.pack("<I", len(body)) + body)
EOF
(sleep 0.5; echo "/img $T/photo.png"; sleep 1; echo "/img $T/photo.webp"; sleep 2) | client alice a >"$T/alice-img2.out" 2>&1
ids=$(grep -ao '/save [0-9]*' "$T/alice-img2.out" | tail -2 | cut -d' ' -f2)
(sleep 1; for i in $ids; do echo "/save $i"; sleep 0.5; done; sleep 1) | client bob b >/dev/null 2>&1
png=$(ls "$T"/home/Downloads/hush-*.png | head -1) webp=$(ls "$T"/home/Downloads/hush-*.webp | head -1)
absent "$png" "GPS" "PNG text chunks are stripped before sending"
check  "$png" "IDAT" "...and the picture data stays"
absent "$webp" "GPS" "WebP EXIF is stripped before sending"
python3 -c "
import struct, sys
d = open(sys.argv[1], 'rb').read()
print('webp riff ok' if struct.unpack('<I', d[4:8])[0] == len(d) - 8 and d[20] & 0x08 == 0 else 'webp riff broken')" "$webp" >"$T/webp.out"
check "$T/webp.out" "webp riff ok" "...and the file stays valid without its EXIF flag"

# My data: everything you sent, and DMs to you, but nobody else's messages.
(sleep 1; echo "/mydata"; sleep 2) | client alice a >"$T/alice-my.out" 2>&1
my=$(ls -d "$T"/home/Downloads/hush-mydata-main-* | head -1)
check  "$T/alice-my.out"      "saved your data"       "/mydata saves your data"
check  "$my/messages.json"    "hello from alice"      "...with your messages"
check  "$my/messages.json"    "while you were out"    "...and DMs sent to you"
absent "$my/messages.json"    "hi alice"              "...but not other people's messages"
[ -f "$my/images/$id.jpg" ] && echo "ok   - ...and your images" || { echo "FAIL - /mydata images"; fail=1; }
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$my/messages.json" &&
    echo "ok   - ...as valid JSON" || { echo "FAIL - /mydata JSON"; fail=1; }

# The operator exports a chat with its key.
HUSH_KEY=zzzz-zzzz-zzzz-zzzz-zzzz-zzzz admin export main "$T/export" >"$T/export.out" 2>&1
check "$T/export.out" "isn't the key" "hushd export needs the chat's key"
HUSH_KEY="$K1" admin export main "$T/export" >"$T/export.out" 2>&1
check  "$T/export.out"              "exported"                  "hushd export decrypts a chat"
check  "$T/export/messages.txt"     "alice: hello from alice"   "...into a readable transcript"
check  "$T/export/messages.txt"     "alice -> bob: [private"    "...with DMs listed, not readable"
absent "$T/export/messages.txt"     "just for you"              "...since the chat key can't open DMs"
check  "$T/export/messages.json"    "\"signature\": \"valid\""  "...and signatures checked"
cmp -s "$T/export/images/$id.jpg" "$T/home/Downloads/hush-$id.jpg" &&
    echo "ok   - ...and images decrypted" || { echo "FAIL - export images"; fail=1; }

# A backup of the running server brings everything back: same chats and counts, and the
# same transcript and images when exported from the backup.
admin backup "$T/backup" >"$T/backup.out" 2>&1
check "$T/backup.out" "backed up" "hushd backup copies a running server"
admin keys >"$T/keys-live.out"
./hushd -C "$T/backup" keys >"$T/keys-backup.out"
cmp -s <(tail -n +2 "$T/keys-live.out") <(tail -n +2 "$T/keys-backup.out") &&
    echo "ok   - ...with every chat and its message and image counts" ||
    { echo "FAIL - backup counts differ"; diff "$T/keys-live.out" "$T/keys-backup.out"; fail=1; }
HUSH_KEY="$K1" ./hushd -C "$T/backup" export main "$T/export-backup" >/dev/null 2>&1
cmp -s <(tail -n +3 "$T/export/messages.txt") <(tail -n +3 "$T/export-backup/messages.txt") &&
    cmp -s "$T/export/images/$id.jpg" "$T/export-backup/images/$id.jpg" &&
    echo "ok   - ...and exporting from the backup gives the same messages and images" ||
    { echo "FAIL - export from backup differs"; fail=1; }

# Nothing readable is stored.
cat "$S"/hushd.db* "$S"/blobs/* >"$T/stored"
for text in "hello from alice" "just for you" "while you were out" "the view" "image/jpeg"; do
    absent "$T/stored" "$text" "the server stores no plaintext ($text)"
done

# Someone with a different key tries to take the name "bob".
sleep 1 | client bob mallory >"$T/mallory.out" 2>&1
check "$T/mallory.out" "name is taken" "server refuses a name owned by another key"

sleep 1 | client eve e zzzz-zzzz-zzzz-zzzz-zzzz-zzzz >"$T/eve.out" 2>&1
check "$T/eve.out" "wrong key" "server refuses a wrong chat key"
sleep 1 | client eve e "$(echo "$K1" | tr 'a-z0' 'A-ZO' | tr -d -)" >"$T/eve2.out" 2>&1
check "$T/eve2.out" "chat: main" "keys work in any case, without dashes, with O for 0"
client eve e not-a-key >"$T/eve3.out" 2>&1 </dev/null
check "$T/eve3.out" "isn't a chat key" "a malformed key is caught before connecting"

# `hushd forget` frees a name.
admin forget bob >/dev/null
sleep 1.2
(sleep 1.5) | client bob mallory >"$T/mallory1.out" 2>&1 &
m=$!
sleep 0.7
admin approve main bob >/dev/null
wait $m
check "$T/mallory1.out" "chat: main" "hushd forget frees a name, without a restart"

# SIGTERM: connected clients are told, and the database is closed cleanly.
(sleep 4) | client alice a >"$T/alice-stop.out" 2>&1 &
a=$!
sleep 1
kill $srv
wait $srv
st=$?
wait $a
[ $st = 0 ] && echo "ok   - hushd exits cleanly on SIGTERM" || { echo "FAIL - hushd exit status $st on SIGTERM"; fail=1; }
check "$T/server.log"     "shutting down"               "...and says so in its log"
check "$T/alice-stop.out" "the server is shutting down" "...and tells connected clients"
[ ! -e "$T/s1/hushd.db-wal" ] && echo "ok   - ...and closes the database (no WAL left)" ||
    { echo "FAIL - WAL left after SIGTERM"; fail=1; }

# The server forgets its registrations (or lies): "bob" shows up with a new key.
S="$T/s2"
mkdir -p "$S"
cp "$T/s1/hushd-keys.txt" "$T/s1/hushd-admins.txt" "$S/"
server "$S"
sleep 1 | client alice a >/dev/null 2>&1
(sleep 0.6; echo "i am totally bob"; sleep 2.5) | client bob b2 >"$T/mallory2.out" 2>&1 &
m=$!
sleep 0.3
admin approve main bob >/dev/null
(sleep 2; echo "/msg bob can you read this?"; sleep 1.5) | client alice a >"$T/alice2.out" 2>&1 &
a=$!
wait $a $m
check  "$T/alice2.out"   "key has CHANGED"                     "alice is warned when bob's key changes"
check  "$T/alice2.out"   "a message from bob isn't shown"      "alice doesn't show messages from the changed key"
check  "$T/alice2.out"   "not sent to bob"                     "alice refuses to encrypt a DM to the changed key"
absent "$T/mallory2.out" "can you read this"                   "impostor never sees alice's DM"
(sleep 1; echo "/fp bob"; echo "/trust bob"; sleep 0.3; echo "/msg bob trusted now"; echo "/verify bob"; echo "/who";
 echo "/help"; sleep 1) | client alice a >"$T/alice-trust.out" 2>&1
check  "$T/alice-trust.out" "their NEW key"           "/fp shows the old and the new key"
check  "$T/alice-trust.out" "accepted bob's new key"  "/trust accepts it"
absent "$T/alice-trust.out" "not sent to bob"         "...and DMs to bob work again"
check  "$T/alice-trust.out" "bob marked as verified"  "/verify marks it verified"
check  "$T/alice-trust.out" "/msg NAME TEXT"          "/help lists the commands"

# The web server.
B="http://127.0.0.1:$WPORT"
curl -s -D "$T/headers" -o "$T/index.html" "$B/"
check "$T/index.html" "Enter key"                       "serves the web client"
check "$T/headers"    "Content-Security-Policy: default-src 'none'" "sends a strict CSP"
check "$T/headers"    "img-src blob:"                   "images only from decrypted data"
check "$T/headers"    "X-Content-Type-Options: nosniff" "sends nosniff"
check "$T/headers"    "frame-ancestors 'none'"          "can't be framed"
{
    echo "traversal $(code --path-as-is "$B/../src/server.c") $(code --path-as-is "$B/%2e%2e/Makefile")"
    echo "unknown $(code "$B/test.sh") $(code "$B/blobs/x") $(code "$B/hushd.db") $(code "$B/hushd-admins.txt")"
    echo "post $(code -X POST "$B/")"
    echo "origin $(code -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Sec-WebSocket-Version: 13' \
        -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Origin: https://evil.example' "$B/ws")"
    echo "garbage $(code -H $'X-Bad: a\x01b' "$B/")"
    echo "health $(code "$B/health") $(curl -s "$B/health")"
} >"$T/http.out"
check "$T/http.out" "traversal 404 404" "no files outside the web client are served"
check "$T/http.out" "unknown 404 404 404 404" "unknown paths, images and server files are 404"
check "$T/http.out" "post 405"          "only GET and HEAD"
check "$T/http.out" "origin 403"        "WebSockets from other sites are refused"
check "$T/http.out" "garbage 400"       "control characters in headers are refused"
check "$T/http.out" "health 200 ok"     "/health answers for uptime checks"

if command -v node >/dev/null; then
    # A web admin lets a web newcomer in.
    echo | web wally >/dev/null 2>&1 # creates wally's identity (he waits, then leaves)
    admin admin "$(fingerprint "$T/web-wally.id")" >/dev/null
    (sleep 2.5; echo "/approve wendy"; sleep 4) | web wally >"$T/wally.out" 2>&1 &
    w1=$!
    sleep 1
    (sleep 3; echo "hello from a browser"; printf '\033[2Jwipe \342\200\256reversed\n'; sleep 0.5;
     echo "/img $T/photo.jpg from the web"; sleep 1;
     echo "/msg alice web dm"; sleep 0.5; echo "/mydata $T/wendy-my.json"; sleep 1) | web wendy >"$T/wendy.out" 2>&1 &
    w2=$!
    (sleep 4; echo "hello from a terminal"; sleep 3) | client alice a >"$T/alice3.out" 2>&1 &
    a=$!
    wait $w1 $w2 $a
    check  "$T/wally.out"  "wendy wants to join"           "a web admin sees who wants to join"
    check  "$T/wendy.out"  "waiting for approval"          "a web newcomer waits"
    check  "$T/wendy.out"  "connected as wendy"            "...and is let in by the web admin"
    check  "$T/alice3.out" "wendy: hello from a browser"   "terminal receives a web client's message"
    check  "$T/alice3.out" "?[2Jwipe ?reversed"            "escape codes and bidi overrides are defused"
    absent "$T/alice3.out" $'\033'                         "...so nothing reaches the terminal raw"
    check  "$T/alice3.out" "[dm] wendy: web dm"            "terminal receives a web client's DM"
    check  "$T/alice3.out" "from the web"                  "terminal receives a web client's image"
    check  "$T/wendy.out"  "alice: hello from a terminal"  "web client receives a terminal message"
    check  "$T/wendy-my.json" "hello from a browser"       "web \"My data\" has your messages"
    (sleep 1; echo "/newchat webclub"; sleep 1.5) | web wally >"$T/wally-new.out" 2>&1
    KW=$(grep -ao 'with key [0-9a-z-]*' "$T/wally-new.out" | cut -d' ' -f3)
    check "$T/wally-new.out" "created webclub" "a web admin creates a chat"
    sleep 1 | client alice a "$KW" >"$T/alice-webclub.out" 2>&1
    check "$T/alice-webclub.out" "chat: webclub" "...whose key works in the terminal"
    (sleep 1; echo "/newchat nope"; sleep 1) | web wendy >"$T/wendy-new.out" 2>&1
    check "$T/wendy-new.out" "only an admin can create chats" "people who aren't admins can't create chats"
    absent "$T/wendy-my.json" "hello from a terminal"      "...and not other people's"
    (sleep 1; echo "/save $T/web-saved.jpg"; sleep 1.5) | web wally >"$T/walter.out" 2>&1
    check  "$T/walter.out" "wendy: hello from a browser"   "web client gets history"
    check  "$T/walter.out" "saved"                         "web client downloads an image"
    cmp -s "$T/photo.jpg" "$T/web-saved.jpg" && echo "ok   - ...and it decrypts to the same bytes" ||
        { echo "FAIL - web image round trip"; fail=1; }
    echo | web eve zzzz-zzzz-zzzz-zzzz-zzzz-zzzz >"$T/eve.out" 2>&1
    check  "$T/eve.out"    "closed: wrong key"             "web client is refused a wrong key"

    # The server checks permissions itself, whatever a modified client sends.
    (sleep 1; echo "/raw 7 01037a6564"; echo "/raw 8 046e6f7065$(printf '%064d' 0)"; sleep 1) |
        web wendy >"$T/wendy-raw.out" 2>&1
    check "$T/wendy-raw.out" "server: only an admin can do that"     "a DECIDE from someone who isn't an admin is refused"
    check "$T/wendy-raw.out" "server: only an admin can create chats" "...and so is a NEWCHAT"
    (sleep 1; echo "/raw 3 00$(printf '%0200d' 0)"; sleep 1) | web wilma >"$T/wilma.out" 2>&1
    check "$T/wilma.out" "closed: protocol violation" "someone on the waitlist can't post"
    (sleep 1; echo "/raw 3 00$(printf '%010000d' 0)"; sleep 1) | web wendy >"$T/wendy-big.out" 2>&1
    check "$T/wendy-big.out" "closed: malformed message" "a message bigger than any client sends is refused"
    (sleep 1; echo "/lastblob"; sleep 0.5) | web wally >"$T/wally-blob.out" 2>&1
    BLOB=$(sed -n 's/^lastblob //p' "$T/wally-blob.out")
    (sleep 1; echo "/raw 6 $BLOB"; sleep 1) | web wally >"$T/fetch-own.out" 2>&1
    (sleep 1; echo "/raw 6 $BLOB"; sleep 1) | web wally "$KW" >"$T/fetch-other.out" 2>&1
    check "$T/fetch-own.out"   "blob $BLOB status 1" "an image can be fetched in its own chat"
    check "$T/fetch-other.out" "blob $BLOB status 2" "...but not from another chat"
else
    echo "skip - web client tests (need node)"
fi

# `hushd clear` empties a chat, `hushd revoke` deletes it and kicks everyone.
admin keys >"$T/keys.out"
check "$T/keys.out" "main" "hushd keys lists chats"
admin clear main >/dev/null
sleep 2 | client alice a >"$T/alice4.out" 2>&1
absent "$T/alice4.out" "hello from a browser" "hushd clear deletes a chat's history"
check  "$T/alice4.out" "chat: main"           "...and the key still works"
(sleep 3) | client carol c "$K2" >"$T/carol2.out" 2>&1 &
c=$!
sleep 1
admin revoke other >/dev/null
wait $c
check "$T/carol2.out" "key was revoked" "hushd revoke disconnects the chat"
sleep 1 | client carol c "$K2" >"$T/carol3.out" 2>&1
check "$T/carol3.out" "wrong key" "a revoked key no longer works"

# Keys from before this version are flagged, not silently broken.
echo "$(printf '%064d' 0) oldchat" >>"$S/hushd-keys.txt"
admin keys >"$T/keys2.out"
check "$T/keys2.out" "old key" "old-format keys are flagged"

# Databases get upgraded in place, and one from a newer hushd is refused.
python3 - "$T/old-db" <<'EOF'
import os, sqlite3, sys
os.makedirs(sys.argv[1], exist_ok=True)
db = sqlite3.connect(sys.argv[1] + "/hushd.db")
db.executescript("""
CREATE TABLE messages (id INTEGER PRIMARY KEY, room BLOB NOT NULL, sender TEXT NOT NULL,
  recipient TEXT, time INTEGER NOT NULL, body BLOB NOT NULL);
CREATE INDEX messages_room ON messages (room, id);
CREATE TABLE members (room BLOB NOT NULL, name TEXT NOT NULL, PRIMARY KEY (room, name));
CREATE TABLE blobs (id BLOB PRIMARY KEY, room BLOB NOT NULL, size INTEGER NOT NULL, time INTEGER NOT NULL);
CREATE INDEX blobs_room ON blobs (room);
INSERT INTO members VALUES (x'00', 'olduser');
""")
db.commit()
EOF
schema() { # db file -> "version N state S" for olduser if present
    python3 -c "
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
row = db.execute(\"SELECT state FROM members WHERE name = 'olduser'\").fetchone()
print('version', db.execute('PRAGMA user_version').fetchone()[0], 'state', row[0] if row else '-')" "$1"
}
./hushd -C "$T/old-db" keys >/dev/null 2>"$T/migrate.out"
schema "$T/old-db/hushd.db" >>"$T/migrate.out"
schema "$S/hushd.db" >"$T/fresh-db.out"
check "$T/migrate.out"  "upgrading hushd.db from schema 1 to 2" "an old database is upgraded in place"
check "$T/migrate.out"  "version 2 state 1" "...and people who were in a chat stay in"
check "$T/fresh-db.out" "version 2"         "a new database starts at the latest schema"
python3 -c "import sqlite3, sys; sqlite3.connect(sys.argv[1]).execute('PRAGMA user_version = 99')" "$T/old-db/hushd.db"
./hushd -C "$T/old-db" keys >"$T/migrate2.out" 2>&1
check "$T/migrate2.out" "written by a newer hushd" "a database from a newer hushd is refused"

# Rate limits, on a fresh server so earlier tests don't count.
kill $srv
wait $srv 2>/dev/null
S="$T/s3"
mkdir -p "$S"
cp "$T/s1/hushd-keys.txt" "$T/s1/hushd-admins.txt" "$S/"
server "$S"
for i in 1 2 3 4 5 6; do sleep 0.2 | client x x zzzz-zzzz-zzzz-zzzz-zzzz-zzzz >"$T/guess$i.out" 2>&1; done
sleep 1 | client alice a >"$T/guess-right.out" 2>&1
check "$T/guess5.out"      "wrong key"           "wrong keys are refused..."
check "$T/guess6.out"      "too many wrong keys" "...until the address is locked out"
check "$T/guess-right.out" "too many wrong keys" "even the right key waits out the lockout"
for i in $(seq 40); do code "$B/style.css"; echo; done >"$T/burst.out"
check "$T/burst.out" "200" "normal requests are served"
check "$T/burst.out" "429" "a burst of requests gets 429"

# Behind a reverse proxy (-x), limits apply to the X-Forwarded-For address.
kill $srv
wait $srv 2>/dev/null
server "$T/s4" -x
for i in $(seq 40); do code -H "X-Forwarded-For: 203.0.113.9" "$B/style.css"; echo; done >"$T/proxy1.out"
code -H "X-Forwarded-For: 203.0.113.9, 198.51.100.7" "$B/style.css" >"$T/proxy2.out"
check "$T/proxy1.out" "429" "limits apply to the forwarded address"
check "$T/proxy2.out" "200" "other forwarded addresses are unaffected"

# Hostile input and a crash, on a fresh server so the rate limits above don't get in the way.
kill $srv
wait $srv 2>/dev/null
S="$T/s5"
mkdir -p "$S"
cp "$T/s1/hushd-keys.txt" "$T/s1/hushd-admins.txt" "$S/"
server "$S"
python3 - "$PORT" "$WPORT" >"$T/malformed.out" <<'EOF'
import socket, struct, sys, time
tcp, web = int(sys.argv[1]), int(sys.argv[2])
def conn(port):
    return socket.create_connection(("127.0.0.1", port), timeout=3)
def read(s, n):
    d = b""
    while len(d) < n:
        c = s.recv(n - len(d))
        if not c:
            return None
        d += c
    return d
def closed(s):
    try:
        while True:
            if not s.recv(4096):
                return "closed"
    except socket.timeout:
        return "still open"
    except ConnectionResetError:
        return "closed"
hello = bytes([5]) + b"probe" + bytes(64) + b"\x01"
frame = struct.pack(">IB", len(hello) + 1, 1) + hello
s = conn(tcp)
for b in frame:
    s.send(bytes([b]))
    time.sleep(0.003)
h = read(s, 5)
print("tcp trickled hello:", "CHALLENGE" if h and h[4] == 10 else h)
s = conn(tcp); s.send(b"\x00\x00\x00\x00\x01"); print("tcp zero length:", closed(s))
s = conn(tcp); s.send(b"\x00\x01\x00\x01\x01"); print("tcp oversized:", closed(s))
s = conn(tcp); s.send(b"\x00\x00\x00\x02\x03\x00"); h = read(s, 5)
print("tcp post before hello:", read(s, struct.unpack(">I", h[:4])[0] - 1).decode() if h else None, closed(s))
def ws():
    s = conn(web)
    s.send((f"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{web}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Origin: http://127.0.0.1:{web}\r\n\r\n").encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(1)
    return s, head.split(b" ")[1].decode()
def masked(op, payload, fin=True, mask=b"abcd"):
    assert len(payload) < 126
    return bytes([(0x80 if fin else 0) | op, 0x80 | len(payload)]) + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
s, code = ws(); s.send(masked(2, bytes([1]) + hello)); h = read(s, 3)
print("ws hello:", code, "CHALLENGE" if h and h[2] == 10 else h)
s, _ = ws(); s.send(bytes([0x82, len(hello) + 1]) + bytes([1]) + hello); print("ws unmasked:", closed(s))
s, _ = ws(); s.send(masked(2, bytes([1]) + hello, fin=False)); print("ws fragment:", closed(s))
s, _ = ws(); s.send(bytes([0x82, 0xff]) + (2**40).to_bytes(8, "big") + b"abcd"); print("ws huge length:", closed(s))
EOF
check "$T/malformed.out" "tcp trickled hello: CHALLENGE"  "a HELLO that arrives a byte at a time still works"
check "$T/malformed.out" "tcp zero length: closed"        "a zero-length frame drops the connection"
check "$T/malformed.out" "tcp oversized: closed"          "an oversized frame drops the connection"
check "$T/malformed.out" "protocol violation closed"      "frames out of order are refused"
check "$T/malformed.out" "ws hello: 101 CHALLENGE"        "the same HELLO works over a WebSocket"
check "$T/malformed.out" "ws unmasked: closed"            "unmasked WebSocket frames are refused"
check "$T/malformed.out" "ws fragment: closed"            "fragmented WebSocket frames are refused"
check "$T/malformed.out" "ws huge length: closed"         "a WebSocket frame claiming 1 TB is refused"

if command -v node >/dev/null; then
    admin admin "$(fingerprint "$T/web-wally.id")" >/dev/null
    for i in $(seq 8); do (sleep 1; echo "/garbage 50"; sleep 0.5) | web wally >>"$T/garbage.out" 2>&1; done
    (sleep 0.5; echo "still here?"; sleep 1) | client alice a >"$T/alice-garbage.out" 2>&1
    check "$T/garbage.out" "connected as wally" "random frames after login..."
    check "$T/garbage.out" "closed: "           "...get the sender dropped..."
    check "$T/alice-garbage.out" "chat: main" "...don't take the server down"

    # kill -9 in the middle of an upload
    head -c 20000000 /dev/urandom >"$T/big.jpg"
    (sleep 1; echo "/img $T/big.jpg"; sleep 20) | web wally >"$T/wally-big.out" 2>&1 &
    w=$!
    for i in $(seq 200); do ls "$S"/blobs/.up-* >/dev/null 2>&1 && break; sleep 0.05; done
    ls "$S"/blobs/.up-* >/dev/null 2>&1 && echo "ok   - an upload is under way" ||
        { echo "FAIL - no upload under way to interrupt"; fail=1; }
    kill -9 $srv
    wait $srv 2>/dev/null
    kill $w 2>/dev/null
    wait $w 2>/dev/null
    server "$S"
    check "$T/server.log" "removed 1 unfinished uploads" "after a crash, the half-uploaded image is removed..."
    ls "$S"/blobs/.up-* >/dev/null 2>&1 && { echo "FAIL - partial upload left"; fail=1; } ||
        echo "ok   - ...and nothing partial is left"
    python3 -c "import sqlite3, sys; print('integrity', sqlite3.connect(sys.argv[1]).execute('PRAGMA integrity_check').fetchone()[0])" \
        "$S/hushd.db" >"$T/integrity.out"
    check "$T/integrity.out" "integrity ok" "...the database is intact"
    sleep 2 | client alice a >"$T/alice-crash.out" 2>&1
    check "$T/alice-crash.out" "alice: still here?" "...and messages from before the crash are still there"
else
    echo "skip - random frames and crash tests (need node)"
fi

kill $srv
wait $srv 2>/dev/null
if grep -qa __asan_init hushd; then
    if ls "$T"/san/* >/dev/null 2>&1; then
        echo "FAIL - sanitizer reports:"
        cat "$T"/san/*
        fail=1
    else
        echo "ok   - no sanitizer reports from any client or server"
    fi
fi

[ $fail = 0 ] && echo "all tests passed" || { echo "some tests failed"; exit 1; }
