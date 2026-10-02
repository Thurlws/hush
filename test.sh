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

check() { # file pattern description
    if grep -qaF -- "$2" "$1"; then echo "ok   - $3"; else echo "FAIL - $3"; echo "---- $1:"; cat "$1"; fail=1; fi
}
absent() { # file pattern description
    if grep -qaF -- "$2" "$1"; then echo "FAIL - $3"; echo "---- $1:"; cat "$1"; fail=1; else echo "ok   - $3"; fi
}
server() { # dir [extra options]: start hushd with its files in dir
    local dir=$1
    shift
    mkdir -p "$dir"
    ./hushd -C "$dir" -p "$PORT" -w "$WPORT" -d "$PWD/web" "$@" 2>>"$T/server.log" &
    srv=$!
    sleep 0.3
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

# The server forgets its registrations (or lies): "bob" shows up with a new key.
kill $srv
wait $srv 2>/dev/null
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
} >"$T/http.out"
check "$T/http.out" "traversal 404 404" "no files outside the web client are served"
check "$T/http.out" "unknown 404 404 404 404" "unknown paths, images and server files are 404"
check "$T/http.out" "post 405"          "only GET and HEAD"
check "$T/http.out" "origin 403"        "WebSockets from other sites are refused"
check "$T/http.out" "garbage 400"       "control characters in headers are refused"

if command -v node >/dev/null; then
    # A web admin lets a web newcomer in.
    echo | web wally >/dev/null 2>&1 # creates wally's identity (he waits, then leaves)
    admin admin "$(fingerprint "$T/web-wally.id")" >/dev/null
    (sleep 2.5; echo "/approve wendy"; sleep 4) | web wally >"$T/wally.out" 2>&1 &
    w1=$!
    sleep 1
    (sleep 3; echo "hello from a browser"; sleep 0.5; echo "/img $T/photo.jpg from the web"; sleep 1;
     echo "/msg alice web dm"; sleep 0.5; echo "/mydata $T/wendy-my.json"; sleep 1) | web wendy >"$T/wendy.out" 2>&1 &
    w2=$!
    (sleep 4; echo "hello from a terminal"; sleep 3) | client alice a >"$T/alice3.out" 2>&1 &
    a=$!
    wait $w1 $w2 $a
    check  "$T/wally.out"  "wendy wants to join"           "a web admin sees who wants to join"
    check  "$T/wendy.out"  "waiting for approval"          "a web newcomer waits"
    check  "$T/wendy.out"  "connected as wendy"            "...and is let in by the web admin"
    check  "$T/alice3.out" "wendy: hello from a browser"   "terminal receives a web client's message"
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

[ $fail = 0 ] && echo "all tests passed" || { echo "some tests failed"; exit 1; }
