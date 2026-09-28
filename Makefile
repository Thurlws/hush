CC      ?= cc
CFLAGS  ?= -O2 -g
# Required flags live apart from CFLAGS so `make CFLAGS=...` can't drop them.
HUSH_CFLAGS = -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic $(shell pkg-config --cflags libsodium)
HUSH_LIBS   = $(shell pkg-config --libs libsodium)
PREFIX  ?= $(HOME)/.local

all: hush hushd

hush: src/client.o src/proto.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(HUSH_LIBS)

hushd: src/server.o src/proto.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(HUSH_LIBS)

src/%.o: src/%.c src/proto.h
	$(CC) $(HUSH_CFLAGS) $(CFLAGS) -c -o $@ $<

install: all
	install -Dm755 hush hushd -t $(PREFIX)/bin

clean:
	rm -f hush hushd src/*.o

.PHONY: all install clean
