CC      ?= cc
CFLAGS  ?= -O2 -g
PREFIX  ?= $(HOME)/.local
# Required flags live apart from CFLAGS so `make CFLAGS=...` can't drop them.
HUSH_CFLAGS = -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic $(shell pkg-config --cflags libsodium sqlite3)
HUSH_LIBS   = $(shell pkg-config --libs libsodium)
HUSHD_LIBS  = $(shell pkg-config --libs sqlite3)
WEB_FILES   = web/index.html web/style.css web/app.js web/hush.js web/sodium.mjs web/libsodium.mjs

all: hush hushd

hush: src/client.o src/proto.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(HUSH_LIBS)

hushd: src/server.o src/web.o src/proto.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(HUSH_LIBS) $(HUSHD_LIBS)

src/%.o: src/%.c src/proto.h src/web.h
	$(CC) $(HUSH_CFLAGS) $(CFLAGS) -c -o $@ $<

install: all
	install -Dm755 hush hushd -t $(PREFIX)/bin
	install -Dm644 $(WEB_FILES) -t $(PREFIX)/share/hush/web

clean:
	rm -f hush hushd src/*.o

.PHONY: all install clean
