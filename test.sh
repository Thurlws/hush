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
    if grep -qF -- "$2" "$1"; then echo "ok   - $3"; else echo "FAIL - $3"; echo "---- $1:"; cat "$1"; fail=1; fi
}
absent() { # file pattern description
    if grep -qF -- "$2" "$1"; then echo "FAIL - $3"; echo "---- $1:"; cat "$1"; fail=1; else echo "ok   - $3"; fi
}
server() { # users-file [extra options]
    ./hushd -p "$PORT" -w "$WPORT" -k "$T/keys.txt" -u "$@" 2>>"$T/server.log" &
    srv=$!
    sleep 0.3
}
client() { # name datadir [key]
    XDG_DATA_HOME="$T/$2" ./hush -n "$1" -k "${3:-$K1}" 127.0.0.1 "$PORT"
}
web() { # name [key]
    node test-web.mjs "$1" "${2:-$K1}" "ws://127.0.0.1:$WPORT/ws" "http://127.0.0.1:$WPORT"
}
newkey() { # label -> prints the key
    ./hushd -k "$T/keys.txt" newkey "$1" | sed -n 's/^    \([0-9a-z-]*\)$/\1/p'
}
code() { # curl args... -> HTTP status
    curl -s -o /dev/null -w "%{http_code}" "$@"
}

K1=$(newkey main)
K2=$(newkey other)
[ -n "$K1" ] && [ -n "$K2" ] && echo "ok   - hushd newkey prints a key" || { echo "FAIL - hushd newkey"; fail=1; }
absent "$T/keys.txt" "$K1" "the keys file holds no plaintext keys"

server "$T/users.txt"

(sleep 1; echo "hello from alice"; sleep 1; echo "/msg bob just for you"; sleep 2) | client alice a >"$T/alice.out" 2>&1 &
a=$!
(sleep 1.5; echo "hi alice"; sleep 1; echo "/who"; sleep 1.5) | client bob b >"$T/bob.out" 2>&1 &
b=$!
(sleep 1.2; echo "anyone?"; sleep 1; echo "/msg alice sneaking in"; sleep 2) | client carol c "$K2" >"$T/carol.out" 2>&1 &
c=$!
wait $a $b $c

check  "$T/bob.out"    "alice: hello from alice"  "bob receives alice's room message"
check  "$T/bob.out"    "[dm] alice: just for you" "bob receives alice's DM"
check  "$T/alice.out"  "bob: hi alice"            "alice receives bob's room message"
check  "$T/alice.out"  "First time seeing them"   "alice pins bob's key on first sight"
check  "$T/bob.out"    "unverified"               "/who shows trust state"
check  "$T/alice.out"  "chat: main"               "clients are told which chat they're in"
absent "$T/server.log" "hello from alice"         "server never logs plaintext"
absent "$T/carol.out"  "hello from alice"         "people in another chat don't see messages"
absent "$T/alice.out"  "carol"                    "people in another chat don't see each other"
check  "$T/carol.out"  "alice is not online"      "no DMs across chats"

# Someone with a different key tries to take the name "bob".
sleep 1 | client bob mallory >"$T/mallory.out" 2>&1
check "$T/mallory.out" "name is taken" "server refuses a name owned by another key"

sleep 1 | client dave d zzzz-zzzz-zzzz-zzzz-zzzz-zzzz >"$T/dave.out" 2>&1
check "$T/dave.out" "wrong key" "server refuses a wrong chat key"
sleep 1 | client dave d "$(echo "$K1" | tr 'a-z0' 'A-ZO' | tr -d -)" >"$T/dave2.out" 2>&1
check "$T/dave2.out" "chat: main" "keys work in any case, without dashes, with O for 0"

# `hushd forget` frees a name.
./hushd -u "$T/users.txt" forget bob >/dev/null
sleep 1.2
sleep 1 | client bob mallory >"$T/mallory1.out" 2>&1
check "$T/mallory1.out" "chat: main" "hushd forget frees a name, without a restart"

# Server forgets its registrations (or lies): "bob" shows up with a new key.
kill $srv; wait $srv 2>/dev/null
server "$T/users2.txt"
(sleep 1; echo "can you read this?"; sleep 1.5) | client alice a >"$T/alice2.out" 2>&1 &
a=$!
(sleep 0.5; echo "i am totally bob"; sleep 2) | client bob b2 >"$T/mallory2.out" 2>&1 &
m=$!
wait $a $m

check  "$T/alice2.out"   "key has CHANGED"            "alice is warned when bob's key changes"
check  "$T/alice2.out"   "dropped a message from bob" "alice drops messages from the changed key"
check  "$T/alice2.out"   "not sent to bob"            "alice refuses to encrypt to the changed key"
absent "$T/mallory2.out" "can you read this"          "impostor never sees alice's message"

# The web server.
B="http://127.0.0.1:$WPORT"
curl -s -D "$T/headers" -o "$T/index.html" "$B/"
check "$T/index.html" "Enter key"                       "serves the web client"
check "$T/headers"    "Content-Security-Policy: default-src 'none'" "sends a strict CSP"
check "$T/headers"    "X-Content-Type-Options: nosniff" "sends nosniff"
check "$T/headers"    "frame-ancestors 'none'"          "can't be framed"
{
    echo "traversal $(code --path-as-is "$B/../src/server.c") $(code --path-as-is "$B/%2e%2e/Makefile")"
    echo "unknown $(code "$B/test.sh")"
    echo "post $(code -X POST "$B/")"
    echo "origin $(code -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Sec-WebSocket-Version: 13' \
        -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Origin: https://evil.example' "$B/ws")"
    echo "garbage $(code -H $'X-Bad: a\x01b' "$B/")"
} >"$T/http.out"
check "$T/http.out" "traversal 404 404" "no files outside the web client are served"
check "$T/http.out" "unknown 404"       "unknown paths are 404"
check "$T/http.out" "post 405"          "only GET and HEAD"
check "$T/http.out" "origin 403"        "WebSockets from other sites are refused"
check "$T/http.out" "garbage 400"       "control characters in headers are refused"

if command -v node >/dev/null; then
    (sleep 1; echo "hello from a browser"; sleep 1; echo "/msg alice web dm"; sleep 1.5) | web wendy >"$T/wendy.out" 2>&1 &
    w=$!
    (sleep 1.3; echo "hello from a terminal"; sleep 2.5) | client alice a >"$T/alice3.out" 2>&1 &
    a=$!
    wait $w $a
    check  "$T/alice3.out" "wendy: hello from a browser"  "terminal receives a web client's message"
    check  "$T/alice3.out" "[dm] wendy: web dm"           "terminal receives a web client's DM"
    check  "$T/wendy.out"  "alice: hello from a terminal" "web client receives a terminal message"
    absent "$T/server.log" "hello from a browser"         "server never logs web plaintext"
    echo | web eve zzzz-zzzz-zzzz-zzzz-zzzz-zzzz >"$T/eve.out" 2>&1
    check  "$T/eve.out"    "closed: wrong key"            "web client is refused a wrong key"
else
    echo "skip - web client tests (need node)"
fi

# Revoking a key disconnects everyone in that chat.
(sleep 3) | client carol c "$K2" >"$T/carol2.out" 2>&1 &
c=$!
sleep 1
./hushd -k "$T/keys.txt" revoke other >/dev/null
wait $c
check "$T/carol2.out" "key was revoked" "hushd revoke disconnects the chat"
sleep 1 | client carol c "$K2" >"$T/carol3.out" 2>&1
check "$T/carol3.out" "wrong key" "a revoked key no longer works"

# Rate limits, on a fresh server so earlier tests don't count.
kill $srv; wait $srv 2>/dev/null
server "$T/users3.txt"
for i in 1 2 3 4 5 6; do sleep 0.2 | client x x zzzz-zzzz-zzzz-zzzz-zzzz-zzzz >"$T/guess$i.out" 2>&1; done
sleep 1 | client alice a >"$T/guess-right.out" 2>&1
check "$T/guess5.out"      "wrong key"          "wrong keys are refused..."
check "$T/guess6.out"      "too many wrong keys" "...until the address is locked out"
check "$T/guess-right.out" "too many wrong keys" "even the right key waits out the lockout"
for i in $(seq 40); do code "$B/style.css"; echo; done >"$T/burst.out"
check "$T/burst.out" "200" "normal requests are served"
check "$T/burst.out" "429" "a burst of requests gets 429"

# Behind a reverse proxy (-x), limits apply to the X-Forwarded-For address.
kill $srv; wait $srv 2>/dev/null
server "$T/users4.txt" -x
for i in $(seq 40); do code -H "X-Forwarded-For: 203.0.113.9" "$B/style.css"; echo; done >"$T/proxy1.out"
code -H "X-Forwarded-For: 203.0.113.9, 198.51.100.7" "$B/style.css" >"$T/proxy2.out"
check "$T/proxy1.out" "429" "limits apply to the forwarded address"
check "$T/proxy2.out" "200" "other forwarded addresses are unaffected"

[ $fail = 0 ] && echo "all tests passed" || { echo "some tests failed"; exit 1; }
