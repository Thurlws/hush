CC      ?= cc
CFLAGS  ?= -O2 -g
PREFIX  ?= $(HOME)/.local
# Required flags live apart from CFLAGS so `make CFLAGS=...` can't drop them.
HUSH_CFLAGS = -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wundef \
              $(shell pkg-config --cflags libsodium sqlite3)
HUSH_LIBS   = $(shell pkg-config --libs libsodium)
HUSHD_LIBS  = $(shell pkg-config --libs sqlite3)
WEB_FILES   = web/index.html web/style.css web/app.js web/hush.js web/sodium.mjs web/libsodium.mjs web/zip.js
SAN         = -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
FUZZ_CC     = clang
FUZZ_FLAGS  = -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all
FUZZERS     = fuzz/http fuzz/ws fuzz/frame fuzz/msg
FUZZ_TIME  ?= 60

all: hush hushd

hush: src/client.o src/msg.o src/proto.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(HUSH_LIBS)

hushd: src/server.o src/web.o src/msg.o src/proto.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(HUSH_LIBS) $(HUSHD_LIBS)

src/%.o: src/%.c src/proto.h src/web.h src/msg.h
	$(CC) $(HUSH_CFLAGS) $(CFLAGS) -c -o $@ $<

tests/unit: tests/unit.c src/msg.o src/proto.o src/web.o src/proto.h src/web.h src/msg.h
	$(CC) $(HUSH_CFLAGS) -Isrc $(CFLAGS) $(LDFLAGS) -o $@ $(filter-out %.h,$^) $(LDLIBS) $(HUSH_LIBS)

fuzz/%: fuzz/%.c src/proto.c src/msg.c src/web.c src/proto.h src/web.h src/msg.h
	$(FUZZ_CC) $(HUSH_CFLAGS) -Isrc $(FUZZ_FLAGS) -o $@ $(filter %.c,$^) $(HUSH_LIBS)

# Each fuzzer runs FUZZ_TIME seconds. New inputs it finds go in fuzz/corpus.
fuzz: $(FUZZERS)
	for f in $(notdir $(FUZZERS)); do \
	    mkdir -p fuzz/corpus/$$f && \
	    ./fuzz/$$f -max_total_time=$(FUZZ_TIME) -artifact_prefix=fuzz/ fuzz/corpus/$$f fuzz/seeds/$$f || exit 1; \
	done

# clang-tidy (checks in .clang-tidy) and gcc's -fanalyzer, any finding fails
analyze:
	clang-tidy --quiet src/*.c tests/unit.c fuzz/*.c -- $(HUSH_CFLAGS) -Isrc
	for f in src/*.c; do gcc $(HUSH_CFLAGS) -O2 -fanalyzer -Werror -c -o /dev/null $$f || exit 1; done

# Line coverage of the unit tests and test.sh together, per file. Cleans up after,
# since instrumented objects can't be linked into a normal build.
coverage:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O0 -g --coverage" LDFLAGS="--coverage" all tests/unit
	./tests/unit
	./test.sh >/dev/null
	@gcov -n -o src src/*.c 2>/dev/null | awk -f tests/coverage.awk
	@$(MAKE) clean >/dev/null

# Objects don't remember their flags, so these rebuild from scratch.
debug:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O0 -g3" all tests/unit

asan:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g $(SAN)" LDFLAGS="$(SAN)" all tests/unit

# Runs against whatever was built last, so `make asan test` tests the sanitizer build.
test: all tests/unit
	./tests/unit
	./test.sh

install: all
	install -Dm755 hush hushd -t $(PREFIX)/bin
	install -Dm644 $(WEB_FILES) -t $(PREFIX)/share/hush/web

clean:
	rm -f hush hushd src/*.o src/*.gcda src/*.gcno tests/unit $(FUZZERS)

.PHONY: all debug asan test fuzz analyze coverage install clean
