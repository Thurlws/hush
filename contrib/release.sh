#!/bin/sh
# Builds the files for a GitHub release into dist/: the source, Linux x86_64 binaries built
# on Ubuntu 24.04, checksums, and release notes from CHANGELOG.md. Needs git, docker and objdump.
# Run from the repo root on a clean, tagged checkout: contrib/release.sh 0.1.0
set -eu
v=${1:?usage: contrib/release.sh VERSION}
die() { echo "$*" >&2; exit 1; }
[ "$(git describe --exact-match --tags HEAD 2>/dev/null)" = "v$v" ] || die "tag HEAD as v$v first"
git diff --quiet HEAD || die "commit or stash your changes first, the binaries are built from this tree"
grep -q "HUSH_VERSION *\"$v\"" src/proto.h || die "src/proto.h has a different HUSH_VERSION"
grep -q "^## $v " CHANGELOG.md || die "CHANGELOG.md has no entry for $v"

rm -rf dist
mkdir dist
git archive --prefix="hush-$v/" -o "dist/hush-$v.tar.gz" "v$v"

bin="hush-$v-linux-x86_64"
docker build --target build -t hush-release-build .
id=$(docker create hush-release-build)
docker cp "$id:/opt/hush" "dist/$bin"
docker rm "$id" >/dev/null
cp LICENSE README.md CHANGELOG.md "dist/$bin/"
glibc=$(objdump -T "dist/$bin/bin/hush" "dist/$bin/bin/hushd" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1 | cut -d_ -f2)
tar -C dist -czf "dist/$bin.tar.gz" "$bin"
rm -rf "dist/$bin"
(cd dist && sha256sum hush-* >SHA256SUMS)

awk -v head="## $v " 'index($0, head) == 1 { on = 1; next } on && /^## / { exit } on' CHANGELOG.md >dist/notes.md
cat >>dist/notes.md <<NOTES

### Binaries

\`$bin.tar.gz\` has \`hush\`, \`hushd\` and the web client, built on Ubuntu 24.04. They need
glibc $glibc or newer (tested on Ubuntu 24.04 and Debian 13, Debian 12 is too old) plus libsodium
and SQLite, which on Ubuntu or Debian is \`sudo apt install libsodium23 libsqlite3-0\`. Unpack it anywhere and run \`bin/hushd\`, which
finds the web client next to itself. Check the download with \`sha256sum -c SHA256SUMS\`.
NOTES
ls -la dist
