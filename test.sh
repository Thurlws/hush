#!/usr/bin/env bash
# End-to-end smoke test: a local server, two scripted clients, then an
# impostor and a key-change scenario. Run from the repo root after `make`.
set -u
cd "$(dirname "$0")"
T=$(mktemp -d)
PORT=${PORT:-17777}
fail=0
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT

check() { # file pattern description
    if grep -qF -- "$2" "$1"; then echo "ok   - $3"; else echo "FAIL - $3"; echo "---- $1:"; cat "$1"; fail=1; fi
}
absent() { # file pattern description
    if grep -qF -- "$2" "$1"; then echo "FAIL - $3"; echo "---- $1:"; cat "$1"; fail=1; else echo "ok   - $3"; fi
}
client() { # name datadir
    XDG_DATA_HOME="$T/$2" ./hush -n "$1" 127.0.0.1 "$PORT"
}

./hushd -p "$PORT" -u "$T/users.txt" 2>"$T/server.log" &
srv=$!
sleep 0.3

(sleep 1; echo "hello from alice"; sleep 1; echo "/msg bob just for you"; sleep 2) | client alice a >"$T/alice.out" 2>&1 &
a=$!
(sleep 1.5; echo "hi alice"; sleep 1; echo "/who"; sleep 1.5) | client bob b >"$T/bob.out" 2>&1 &
b=$!
wait $a $b

check  "$T/bob.out"    "alice: hello from alice"  "bob receives alice's room message"
check  "$T/bob.out"    "[dm] alice: just for you" "bob receives alice's DM"
check  "$T/alice.out"  "bob: hi alice"            "alice receives bob's room message"
check  "$T/alice.out"  "First time seeing them"   "alice pins bob's key on first sight"
check  "$T/bob.out"    "unverified"               "/who shows trust state"
absent "$T/server.log" "hello from alice"         "server never logs plaintext"

# Someone with a different key tries to take the name "bob".
sleep 1 | client bob mallory >"$T/mallory.out" 2>&1
check "$T/mallory.out" "belongs to a different key" "server refuses a name owned by another key"

# Server forgets its registrations (or lies): "bob" shows up with a new key.
kill $srv; wait $srv 2>/dev/null
./hushd -p "$PORT" -u "$T/users2.txt" 2>>"$T/server.log" &
srv=$!
sleep 0.3
(sleep 1; echo "can you read this?"; sleep 1.5) | client alice a >"$T/alice2.out" 2>&1 &
a=$!
(sleep 0.5; echo "i am totally bob"; sleep 2) | client bob mallory >"$T/mallory2.out" 2>&1 &
m=$!
wait $a $m

check  "$T/alice2.out"   "key has CHANGED"            "alice is warned when bob's key changes"
check  "$T/alice2.out"   "dropped a message from bob" "alice drops messages from the changed key"
check  "$T/alice2.out"   "not sent to bob"            "alice refuses to encrypt to the changed key"
absent "$T/mallory2.out" "can you read this"          "impostor never sees alice's message"

[ $fail = 0 ] && echo "all tests passed" || { echo "some tests failed"; exit 1; }
