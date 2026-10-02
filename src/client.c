/* hush: end-to-end encrypted chat client for the terminal.
 *
 * Identity: one ed25519 keypair per user (~/.local/share/hush/identity.key).
 * It signs the login challenge and every message you send, and, converted to
 * X25519, encrypts DMs with crypto_box.
 *
 * Chat messages use a key derived from the chat key (see proto.h) that the
 * server never sees. Everyone in the chat, including people who join later,
 * can read the stored history.
 *
 * Trust: the first key seen for a name is pinned in known_peers. A different
 * key later is refused until the user runs /trust. Comparing fingerprints
 * out of band (/fp, /verify) rules out a lying server. */
#include "msg.h"
#include "proto.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define MAX_PEERS  256
#define SEEN_MAX   4096 /* message ids remembered, to drop repeats */
#define IMAGES_MAX 256  /* images remembered for /save */
#define WAITING_MAX 64 /* people shown to an admin as waiting to join */
#define NONCE      MSG_NONCE
#define MAC        MSG_MAC
#define PLAIN_HEAD MSG_HEAD
#define HISTORY_PAGE 30

enum { TRUST_OK, TRUST_CHANGED, TRUST_BAD };

struct known {
    char name[HUSH_NAME_MAX + 1];
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    int verified;
};

struct peer {
    char name[HUSH_NAME_MAX + 1];
    uint8_t pk[crypto_sign_PUBLICKEYBYTES]; /* key the server announced */
    uint8_t key[crypto_box_BEFORENMBYTES];  /* precomputed DM key */
    int online, trust;
};

struct image {
    uint64_t msg_id;
    uint8_t file_key[32], blob[HUSH_BLOB_ID];
    uint32_t size;
    char mime[32];
};

static struct known *known;
static size_t nknown;
static char known_path[4200];
static struct peer peers[MAX_PEERS];
static size_t npeers;

static char my_name[HUSH_NAME_MAX + 1];
static char chat_key_text[HUSH_KEY_MAX + 2], chat_label[HUSH_NAME_MAX + 1];
static uint8_t my_pk[crypto_sign_PUBLICKEYBYTES], my_sk[crypto_sign_SECRETKEYBYTES];
static uint8_t my_xsk[crypto_scalarmult_BYTES];
static uint8_t token[32], chat_key[32], chat_id[32];

static uint8_t seen[SEEN_MAX][16];
static size_t nseen;
static struct image images[IMAGES_MAX];
static size_t nimages;
static uint64_t oldest_id; /* for /more */
static int more_history;
static int am_admin;
static char waiting[WAITING_MAX][HUSH_NAME_MAX + 1];
static size_t nwaiting;
/* /newchat: the key we made, shown once the server has the chat */
static char new_key[HUSH_KEY_CHARS + HUSH_KEY_CHARS / 4], new_label[HUSH_NAME_MAX + 1];

/* One image going up, one coming down. */
static struct {
    int active;
    uint8_t file_key[32];
    uint32_t size;
    uint16_t w, h;
    char mime[32], caption[HUSH_MAX_TEXT + 1];
} upload;
static struct {
    int active, for_mydata;
    struct image img;
    struct buf data;
    char path[4300]; /* save path, empty means ~/Downloads */
} download;
/* /mydata: everything you sent, and DMs sent to you, saved to a folder. */
static struct {
    int active;
    char dir[4200];
    FILE *json;
    long count;
    uint64_t last_id;
    struct image *queue;
    size_t nqueue, next;
} mydata;

static int sock = -1;
static struct buf rx, tx;
static int interactive, ui_ready;
static volatile sig_atomic_t running = 1;
static struct termios orig_tio;
static int raw_on;
static char line[HUSH_MAX_TEXT + 1];
static size_t line_len;
static int esc_state;

static const char *col(const char *seq)
{
    return interactive ? seq : "";
}

static void redraw(void)
{
    if (!interactive || !ui_ready)
        return;
    struct winsize ws;
    size_t cols = 80;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 8)
        cols = ws.ws_col;
    /* show only the tail of a long line so it never wraps */
    size_t avail = cols - 4, start = 0, cps = 0;
    for (size_t i = 0; i < line_len; i++)
        cps += (line[i] & 0xC0) != 0x80;
    while (cps > avail) {
        do
            start++;
        while (start < line_len && (line[start] & 0xC0) == 0x80);
        cps--;
    }
    printf("\r\033[K\033[1;32m>\033[0m %.*s", (int)(line_len - start), line + start);
    fflush(stdout);
}

/* Print a line above the input prompt. */
__attribute__((format(printf, 1, 2))) static void say(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (interactive && ui_ready)
        printf("\r\033[K");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    redraw();
    fflush(stdout);
}

static void term_restore(void)
{
    if (!raw_on)
        return;
    raw_on = 0;
    printf("\r\033[K");
    fflush(stdout);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_tio);
}

static void term_raw(void)
{
    if (tcgetattr(STDIN_FILENO, &orig_tio) < 0)
        die("tcgetattr: %s", strerror(errno));
    struct termios t = orig_tio;
    t.c_iflag &= ~(tcflag_t)(ICRNL | IXON | BRKINT | ISTRIP | INPCK);
    t.c_lflag &= ~(tcflag_t)(ECHO | ICANON | ISIG | IEXTEN);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    raw_on = 1;
    atexit(term_restore);
}

/* Copy untrusted text for display, dropping C0/C1 control codes (escape
 * sequences) and invalid UTF-8. dst must hold n + 1 bytes. */
static void sanitize(const uint8_t *s, size_t n, char *dst)
{
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        uint8_t c = s[i];
        if (c < 0x80) {
            dst[o++] = (char)(c >= 0x20 && c != 0x7f ? c : (c == '\t' || c == '\n') ? ' ' : '?');
            i++;
            continue;
        }
        size_t len = c >= 0xC2 && c <= 0xDF ? 2 : c >= 0xE0 && c <= 0xEF ? 3 : c >= 0xF0 && c <= 0xF4 ? 4 : 0;
        int ok = len && i + len <= n;
        for (size_t j = 1; ok && j < len; j++)
            ok = (s[i + j] & 0xC0) == 0x80;
        if (ok) {
            uint8_t c1 = s[i + 1];
            if ((c == 0xC2 && c1 < 0xA0) ||   /* C1 controls */
                (c == 0xE0 && c1 < 0xA0) ||   /* overlong */
                (c == 0xED && c1 >= 0xA0) ||  /* surrogates */
                (c == 0xF0 && c1 < 0x90) ||   /* overlong */
                (c == 0xF4 && c1 >= 0x90))    /* > U+10FFFF */
                ok = 0;
        }
        if (!ok) {
            dst[o++] = '?';
            i++;
            continue;
        }
        memcpy(dst + o, s + i, len);
        o += len;
        i += len;
    }
    dst[o] = '\0';
}

static int name_color(const char *name)
{
    unsigned h = 5381;
    while (*name)
        h = h * 33 + (unsigned char)*name++;
    return 31 + (int)(h % 6);
}

/* "14:05" today, else "Mar 3 14:05". */
static void format_time(uint64_t ms, char *out, size_t n)
{
    time_t t = (time_t)(ms / 1000), now = time(NULL);
    struct tm a, b;
    localtime_r(&t, &a);
    localtime_r(&now, &b);
    strftime(out, n, a.tm_yday == b.tm_yday && a.tm_year == b.tm_year ? "%H:%M" : "%b %e %H:%M", &a);
}

static void show_line(uint64_t ms, const char *from, const char *to, const char *text)
{
    char ts[32], color[16], tag[64] = "";
    format_time(ms, ts, sizeof ts);
    snprintf(color, sizeof color, "\033[1;%dm", name_color(from));
    if (*to && !strcmp(from, my_name))
        snprintf(tag, sizeof tag, "%s[dm to %s]%s ", col("\033[35m"), to, col("\033[0m"));
    else if (*to)
        snprintf(tag, sizeof tag, "%s[dm]%s ", col("\033[35m"), col("\033[0m"));
    say("%s%s%s %s%s%s%s: %s", col("\033[2m"), ts, col("\033[0m"), tag, col(color), from,
        col("\033[0m"), text);
}

static void mkdir_p(char *path)
{
    for (char *p = path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(path, 0700);
            *p = '/';
        }
    }
    if (mkdir(path, 0700) < 0 && errno != EEXIST)
        die("cannot create %s: %s", path, strerror(errno));
}

static void identity_load(const char *dir)
{
    char path[4200];
    snprintf(path, sizeof path, "%s/identity.key", dir);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t r = read(fd, my_sk, sizeof my_sk);
        close(fd);
        if (r != (ssize_t)sizeof my_sk)
            die("%s is corrupt", path);
        crypto_sign_ed25519_sk_to_pk(my_pk, my_sk);
    } else if (errno == ENOENT) {
        crypto_sign_keypair(my_pk, my_sk);
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0 || write(fd, my_sk, sizeof my_sk) != (ssize_t)sizeof my_sk || close(fd) < 0)
            die("cannot write %s: %s", path, strerror(errno));
        fprintf(stderr, "hush: created a new identity in %s\n", path);
    } else {
        die("cannot read %s: %s", path, strerror(errno));
    }
    if (crypto_sign_ed25519_sk_to_curve25519(my_xsk, my_sk) != 0)
        die("%s holds an unusable key", path);
}

static struct known *known_find(const char *name)
{
    for (size_t i = 0; i < nknown; i++)
        if (!strcmp(known[i].name, name))
            return &known[i];
    return NULL;
}

static struct known *known_add(const char *name, const uint8_t *pk, int verified)
{
    struct known *p = realloc(known, (nknown + 1) * sizeof *known);
    if (!p)
        die("out of memory");
    known = p;
    struct known *k = &known[nknown++];
    strcpy(k->name, name);
    memcpy(k->pk, pk, sizeof k->pk);
    k->verified = verified;
    return k;
}

static void known_load(void)
{
    FILE *f = fopen(known_path, "r");
    if (!f)
        return;
    char name[64], hex[128], state[16];
    while (fscanf(f, "%63s %127s %15s", name, hex, state) == 3) {
        uint8_t pk[crypto_sign_PUBLICKEYBYTES];
        size_t bl;
        if (name_valid(name, strlen(name)) && !known_find(name) &&
            sodium_hex2bin(pk, sizeof pk, hex, strlen(hex), NULL, &bl, NULL) == 0 && bl == sizeof pk)
            known_add(name, pk, !strcmp(state, "verified"));
    }
    fclose(f);
}

static void known_save(void)
{
    char tmp[4300];
    snprintf(tmp, sizeof tmp, "%s.tmp", known_path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        say("! cannot save %s: %s", tmp, strerror(errno));
        return;
    }
    for (size_t i = 0; i < nknown; i++) {
        char hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
        sodium_bin2hex(hex, sizeof hex, known[i].pk, sizeof known[i].pk);
        fprintf(f, "%s %s %s\n", known[i].name, hex, known[i].verified ? "verified" : "unverified");
    }
    if (fclose(f) != 0 || rename(tmp, known_path) != 0)
        say("! cannot save %s: %s", known_path, strerror(errno));
}

static int dial(const char *host, const char *port)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *res, *ai;
    int err = getaddrinfo(host, port, &hints, &res);
    if (err)
        die("cannot resolve %s: %s", host, gai_strerror(err));
    int fd = -1;
    for (ai = res; ai && fd < 0; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd >= 0 && connect(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
            err = errno;
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(res);
    if (fd < 0)
        die("cannot connect to %s port %s: %s", host, port, strerror(err));
    return fd;
}

static void net_send_raw(uint8_t type, const void *p, size_t n)
{
    tx.len = 0;
    frame_put(&tx, type, p, n);
    for (size_t off = 0; off < tx.len;) {
        /* NOLINTNEXTLINE(clang-analyzer-unix.StdCLibraryFunctions): sock is open by now */
        ssize_t r = send(sock, tx.data + off, tx.len - off, MSG_NOSIGNAL);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0) {
            say("! lost connection to the server");
            running = 0;
            return;
        }
        off += (size_t)r;
    }
}

static void net_send(uint8_t type, const struct buf *payload)
{
    net_send_raw(type, payload->data, payload->len);
}

/* Block until a whole frame is buffered (handshake only). */
static void read_frame(uint8_t *type, const uint8_t **p, size_t *n, size_t *fs)
{
    for (;;) {
        int k = frame_peek(&rx, type, p, n, fs);
        if (k > 0)
            return;
        if (k < 0)
            die("server sent a malformed frame");
        buf_reserve(&rx, 16384);
        /* NOLINTNEXTLINE(clang-analyzer-unix.StdCLibraryFunctions): sock is open by now */
        ssize_t r = recv(sock, rx.data + rx.len, rx.cap - rx.len, 0);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            die("server closed the connection during login");
        rx.len += (size_t)r;
    }
}

static void expect(uint8_t want, const uint8_t **p, size_t *n, size_t *fs)
{
    uint8_t type;
    read_frame(&type, p, n, fs);
    if (type == T_ERROR) {
        char msg[HUSH_MAX_FRAME + 1];
        sanitize(*p, *n, msg);
        die("server refused login: %s", msg);
    }
    if (type != want)
        die("unexpected reply from server during login");
}

static void handshake(void)
{
    struct buf b = { 0 };
    const uint8_t *p;
    size_t n, fs;

    name_put(&b, my_name);
    buf_put(&b, my_pk, sizeof my_pk);
    buf_put(&b, token, sizeof token);
    uint8_t version = HUSH_PROTO;
    buf_put(&b, &version, 1);
    net_send(T_HELLO, &b);

    expect(T_CHALLENGE, &p, &n, &fs);
    if (n != HUSH_CHALLENGE_LEN)
        die("bad challenge from server");
    uint8_t msg[sizeof HUSH_AUTH_CONTEXT - 1 + HUSH_CHALLENGE_LEN];
    memcpy(msg, HUSH_AUTH_CONTEXT, sizeof HUSH_AUTH_CONTEXT - 1);
    memcpy(msg + sizeof HUSH_AUTH_CONTEXT - 1, p, HUSH_CHALLENGE_LEN);
    buf_consume(&rx, fs);

    uint8_t sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, msg, sizeof msg, my_sk);
    b.len = 0;
    buf_put(&b, sig, sizeof sig);
    net_send(T_AUTH, &b);
    buf_free(&b);

    /* WAITING until an admin lets us in, then WELCOME */
    for (;;) {
        uint8_t type;
        read_frame(&type, &p, &n, &fs);
        if (type == T_ERROR) {
            char err[HUSH_MAX_FRAME + 1];
            sanitize(p, n, err);
            die("server refused login: %s", err);
        }
        int k = name_get(p, n, chat_label);
        if (k < 0 || (type != T_WAITING && type != T_WELCOME))
            die("unexpected reply from server during login");
        if (type == T_WELCOME) {
            am_admin = (size_t)k < n && (p[k] & WELCOME_ADMIN);
            buf_consume(&rx, fs);
            return;
        }
        char fp[HUSH_FP_LEN];
        fingerprint(my_pk, fp);
        printf("You're on the waitlist for \"%s\": an admin has to let you in.\n"
               "They'll see your fingerprint, %s, so they can check it's you.\n"
               "Waiting... (Ctrl-C to give up)\n",
               chat_label, fp);
        fflush(stdout);
        buf_consume(&rx, fs);
    }
}

static void request_history(int dir, uint64_t anchor, uint16_t limit)
{
    uint8_t p[11];
    p[0] = (uint8_t)dir;
    put_u64(p + 1, anchor);
    put_u16(p + 9, limit);
    net_send_raw(T_HISTORY, p, sizeof p);
}

static struct peer *peer_find(const char *name)
{
    for (size_t i = 0; i < npeers; i++)
        if (!strcmp(peers[i].name, name))
            return &peers[i];
    return NULL;
}

static int peer_derive(struct peer *pe)
{
    uint8_t xpk[crypto_scalarmult_BYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(xpk, pe->pk) != 0 ||
        crypto_box_beforenm(pe->key, xpk, my_xsk) != 0)
        return -1;
    return 0;
}

static void on_peer(const uint8_t *p, size_t n)
{
    char name[HUSH_NAME_MAX + 1], fp[HUSH_FP_LEN], oldfp[HUSH_FP_LEN];
    int k = name_get(p, n, name);
    if (k < 0 || n - (size_t)k != crypto_sign_PUBLICKEYBYTES + 1 || !strcmp(name, my_name))
        return;
    const uint8_t *pk = p + k;
    int flags = p[(size_t)k + crypto_sign_PUBLICKEYBYTES];

    struct peer *pe = peer_find(name);
    if (!pe) {
        if (npeers == MAX_PEERS)
            return;
        pe = &peers[npeers++];
        memset(pe, 0, sizeof *pe);
        strcpy(pe->name, name);
    }
    int was_online = pe->online;
    memcpy(pe->pk, pk, sizeof pe->pk);
    pe->online = flags & PEER_ONLINE;
    fingerprint(pk, fp);

    struct known *kn = known_find(name);
    int first = !kn;
    if (first) {
        kn = known_add(name, pk, 0);
        known_save();
    }
    pe->trust = sodium_memcmp(kn->pk, pk, sizeof kn->pk) ? TRUST_CHANGED : TRUST_OK;
    if (pe->trust == TRUST_OK && peer_derive(pe) != 0)
        pe->trust = TRUST_BAD;

    const char *what = flags & PEER_NEW ? "joined the chat" : pe->online ? "is online" : "is in this chat";
    if (pe->trust == TRUST_BAD) {
        say("%s! %s presented an invalid key; ignoring them%s", col("\033[1;31m"), name, col("\033[0m"));
    } else if (pe->trust == TRUST_CHANGED) {
        fingerprint(kn->pk, oldfp);
        say("%s!!! WARNING: %s's key has CHANGED !!!%s\n"
            "    Either they reset their identity, or someone (the server?) is trying to\n"
            "    pose as them. Nothing will be sent to or accepted from them.\n"
            "    pinned: %s\n    now:    %s\n"
            "    Call them, compare the new fingerprint, then run /trust %s",
            col("\033[1;31m"), name, col("\033[0m"), oldfp, fp, name);
    } else if (first) {
        say("%s* %s %s%s. First time seeing them: fingerprint %s%s%s\n"
            "  Compare it with them on another channel (e.g. a call), then run /verify %s",
            col("\033[33m"), name, what, col("\033[0m"), col("\033[1m"), fp, col("\033[0m"), name);
    } else if (pe->online && !was_online) {
        say("%s* %s %s%s%s", col("\033[33m"), name, what, kn->verified ? "" : " (unverified)",
            col("\033[0m"));
    }
}

static void on_leave(const uint8_t *p, size_t n)
{
    char name[HUSH_NAME_MAX + 1];
    struct peer *pe;
    if (name_get(p, n, name) < 0 || !(pe = peer_find(name)))
        return;
    pe->online = 0;
    say("%s* %s went offline%s", col("\033[33m"), name, col("\033[0m"));
}

static void sign_data(struct buf *d, const uint8_t *plain, size_t n)
{
    d->len = 0;
    buf_put(d, HUSH_MSG_CONTEXT, sizeof HUSH_MSG_CONTEXT - 1);
    buf_put(d, chat_id, sizeof chat_id);
    buf_put(d, plain, n);
}

/* Build, sign, encrypt and post a message. to is NULL for the chat. */
static void post(const struct peer *to, int kind, const void *content, size_t cn)
{
    struct buf plain = { 0 }, sd = { 0 }, out = { 0 };
    uint8_t head[PLAIN_HEAD];
    head[0] = HUSH_MSG_VERSION;
    head[1] = (uint8_t)kind;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    put_u64(head + 2, (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
    randombytes_buf(head + 10, 16);
    buf_put(&plain, head, sizeof head);
    name_put(&plain, my_name);
    name_put(&plain, to ? to->name : "");
    buf_put(&plain, content, cn);
    uint8_t sig[crypto_sign_BYTES];
    sign_data(&sd, plain.data, plain.len);
    crypto_sign_detached(sig, NULL, sd.data, sd.len, my_sk);
    buf_put(&plain, sig, sizeof sig);

    name_put(&out, to ? to->name : "");
    size_t at = out.len;
    buf_reserve(&out, NONCE + plain.len + MAC);
    uint8_t *nonce = out.data + at, *ct = nonce + NONCE;
    randombytes_buf(nonce, NONCE);
    if (to) {
        crypto_box_easy_afternm(ct, plain.data, plain.len, nonce, to->key);
        out.len = at + NONCE + plain.len + crypto_box_MACBYTES;
    } else {
        unsigned long long cl;
        crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &cl, plain.data, plain.len, NULL, 0, NULL, nonce,
                                                   chat_key);
        out.len = at + NONCE + (size_t)cl;
    }
    net_send(T_POST, &out);
    sodium_memzero(plain.data, plain.len);
    buf_free(&plain);
    buf_free(&sd);
    buf_free(&out);
}

static int seen_before(const uint8_t *id)
{
    size_t n = nseen < SEEN_MAX ? nseen : SEEN_MAX;
    for (size_t i = 0; i < n; i++)
        if (!memcmp(seen[i], id, 16))
            return 1;
    memcpy(seen[nseen++ % SEEN_MAX], id, 16);
    return 0;
}

/* A MSG frame, decrypted and checked. The plaintext lives in opened_plain
 * until the next one is opened. */
struct opened {
    uint64_t id;
    int live;
    char from[HUSH_NAME_MAX + 1], to[HUSH_NAME_MAX + 1];
    struct hush_msg m;
};
static uint8_t opened_plain[HUSH_MAX_FRAME];

/* 0 with o filled in, or -1 after saying why the message isn't shown. */
static int open_msg(const uint8_t *p, size_t n, struct opened *o)
{
    if (n < 17)
        return -1;
    o->id = get_u64(p);
    o->live = p[16];
    int k1 = name_get(p + 17, n - 17, o->from), k2;
    if (k1 < 0 || (k2 = name_get_opt(p + 17 + k1, n - 17 - (size_t)k1, o->to)) < 0)
        return -1;
    const uint8_t *body = p + 17 + k1 + k2;
    size_t bl = n - 17 - (size_t)k1 - (size_t)k2;

    int mine = !strcmp(o->from, my_name);
    struct peer *pe = mine ? NULL : peer_find(o->from);
    if (!mine && (!pe || pe->trust != TRUST_OK)) {
        say("! a message from %s isn't shown: %s", o->from,
            pe ? "their key changed (see /help)" : "unknown sender");
        return -1;
    }
    const uint8_t *dm_key = NULL;
    if (*o->to) {
        struct peer *dm = peer_find(mine ? o->to : o->from);
        if (dm && dm->trust == TRUST_OK)
            dm_key = dm->key;
    }
    long pl = (*o->to && !dm_key) || bl > sizeof opened_plain ? -1
                                                               : msg_decrypt(body, bl, chat_key, dm_key, opened_plain);
    if (pl < 0) {
        say("! a message from %s failed to decrypt (tampered with?)", o->from);
        return -1;
    }
    if (msg_parse(opened_plain, (size_t)pl, &o->m) != 0 || strcmp(o->m.from, o->from) ||
        strcmp(o->m.to, o->to)) {
        say("! dropped a message relabelled as coming from %s", o->from);
        return -1;
    }
    if (msg_verify(opened_plain, &o->m, chat_id, mine ? my_pk : pe->pk) != 0) {
        say("! a message claiming to be from %s has a bad signature", o->from);
        return -1;
    }
    return 0;
}

static void remember_image(uint64_t msg_id, const struct hush_image *hi, struct image *im)
{
    im->msg_id = msg_id;
    memcpy(im->file_key, hi->file_key, 32);
    memcpy(im->blob, hi->blob, HUSH_BLOB_ID);
    im->size = hi->size;
    strcpy(im->mime, hi->mime);
}

static void show_msg(const struct opened *o)
{
    const struct hush_msg *m = &o->m;
    char text[HUSH_MAX_TEXT + 200], caption[HUSH_MAX_TEXT + 1];
    struct hush_image hi;
    if (m->kind == KIND_TEXT) {
        sanitize(m->content, m->content_len > HUSH_MAX_TEXT ? HUSH_MAX_TEXT : m->content_len, text);
    } else if (m->kind == KIND_IMAGE && image_parse(m->content, m->content_len, &hi) == 0) {
        remember_image(o->id, &hi, &images[nimages++ % IMAGES_MAX]);
        sanitize(hi.caption, hi.caption_len > HUSH_MAX_TEXT ? HUSH_MAX_TEXT : hi.caption_len, caption);
        snprintf(text, sizeof text, "%s[image %ux%u, %.1f MB, /save %llu]%s%s%s", col("\033[36m"), hi.width,
                 hi.height, hi.size / 1048576.0, (unsigned long long)o->id, col("\033[0m"), *caption ? " " : "",
                 caption);
    } else {
        snprintf(text, sizeof text, "[something this version can't show]");
    }
    show_line(m->time, o->from, o->to, text);
}

static void iso_time(uint64_t ms, char *out, size_t n)
{
    time_t t = (time_t)(ms / 1000);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void mydata_entry(const uint8_t *p, size_t n)
{
    struct opened o;
    if (n >= 8)
        mydata.last_id = get_u64(p);
    FILE *f = mydata.json;
    fprintf(f, "%s\n    {\"id\": %llu", mydata.count++ ? "," : "", (unsigned long long)mydata.last_id);
    if (open_msg(p, n, &o) != 0) {
        fprintf(f, ", \"error\": \"could not be decrypted or verified\"}");
        return;
    }
    char when[64];
    struct hush_image hi;
    iso_time(o.m.time, when, sizeof when);
    fprintf(f, ", \"time\": \"%s\", \"from\": ", when);
    json_string(f, (const uint8_t *)o.from, strlen(o.from));
    if (*o.to) {
        fprintf(f, ", \"to\": ");
        json_string(f, (const uint8_t *)o.to, strlen(o.to));
    }
    if (o.m.kind == KIND_TEXT) {
        fprintf(f, ", \"text\": ");
        json_string(f, o.m.content, o.m.content_len);
    } else if (o.m.kind == KIND_IMAGE && image_parse(o.m.content, o.m.content_len, &hi) == 0) {
        struct image *q = realloc(mydata.queue, (mydata.nqueue + 1) * sizeof *q);
        if (!q)
            die("out of memory");
        mydata.queue = q;
        remember_image(o.id, &hi, &q[mydata.nqueue++]);
        fprintf(f, ", \"image\": \"images/%llu.%s\", \"caption\": ", (unsigned long long)o.id, image_ext(hi.mime));
        json_string(f, hi.caption, hi.caption_len);
    }
    fprintf(f, "}");
}

static void start_download(const struct image *im, const char *path, int for_mydata)
{
    download.active = 1;
    download.for_mydata = for_mydata;
    download.img = *im;
    download.data.len = 0;
    snprintf(download.path, sizeof download.path, "%s", path ? path : "");
    net_send_raw(T_FETCH, im->blob, HUSH_BLOB_ID);
}

/* Fetch the queued images one at a time, then close the file. */
static void mydata_next(void)
{
    if (mydata.next < mydata.nqueue) {
        const struct image *im = &mydata.queue[mydata.next++];
        char path[4300];
        snprintf(path, sizeof path, "%s/images/%llu.%s", mydata.dir, (unsigned long long)im->msg_id,
                 image_ext(im->mime));
        start_download(im, path, 1);
        return;
    }
    fprintf(mydata.json, "\n  ]\n}\n");
    if (fclose(mydata.json) != 0)
        say("! cannot write %s/messages.json: %s", mydata.dir, strerror(errno));
    else
        say("saved your data (%ld messages, %zu images) to %s", mydata.count, mydata.nqueue, mydata.dir);
    free(mydata.queue);
    memset(&mydata, 0, sizeof mydata);
}

static void cmd_mydata(void)
{
    if (mydata.active || download.active) {
        say("! wait for the download that's running to finish");
        return;
    }
    char base[4096], stamp[32], path[4300], fp[HUSH_FP_LEN];
    const char *home = getenv("HOME");
    struct stat st;
    time_t now = time(NULL);
    snprintf(base, sizeof base, "%s/Downloads", home ? home : ".");
    if (!home || stat(base, &st) < 0 || !S_ISDIR(st.st_mode))
        strcpy(base, ".");
    strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%S", localtime(&now));
    snprintf(mydata.dir, sizeof mydata.dir, "%s/hush-mydata-%s-%s", base, chat_label, stamp);
    snprintf(path, sizeof path, "%s/images", mydata.dir);
    if (mkdir(mydata.dir, 0700) < 0 || mkdir(path, 0700) < 0) {
        say("! cannot create %s: %s", path, strerror(errno));
        return;
    }
    snprintf(path, sizeof path, "%s/messages.json", mydata.dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 || !(mydata.json = fdopen(fd, "w"))) {
        say("! cannot create %s: %s", path, strerror(errno));
        return;
    }
    char when[64];
    iso_time((uint64_t)now * 1000, when, sizeof when);
    fingerprint(my_pk, fp);
    fprintf(mydata.json, "{\n  \"chat\": ");
    json_string(mydata.json, (const uint8_t *)chat_label, strlen(chat_label));
    fprintf(mydata.json, ",\n  \"name\": ");
    json_string(mydata.json, (const uint8_t *)my_name, strlen(my_name));
    fprintf(mydata.json, ",\n  \"fingerprint\": \"%s\",\n  \"exported\": \"%s\",\n"
                         "  \"contents\": \"everything you sent in this chat, and the private messages sent to you\",\n"
                         "  \"messages\": [", fp, when);
    mydata.active = 1;
    say("saving your data to %s ...", mydata.dir);
    request_history(HIST_MINE, 0, HUSH_HISTORY_MAX);
}

static void on_msg(const uint8_t *p, size_t n)
{
    if (n < 17)
        return;
    if (mydata.active && !p[16]) { /* a page of /mydata */
        mydata_entry(p, n);
        return;
    }
    uint64_t id = get_u64(p);
    if (!p[16] && (!oldest_id || id < oldest_id))
        oldest_id = id;
    struct opened o;
    if (open_msg(p, n, &o) == 0 && !seen_before(o.m.uid))
        show_msg(&o);
    sodium_memzero(opened_plain, sizeof opened_plain);
}

static void on_history_end(const uint8_t *p, size_t n)
{
    if (n != 2)
        return;
    if (p[0] == HIST_MINE && mydata.active) {
        if (p[1])
            request_history(HIST_MINE, mydata.last_id, HUSH_HISTORY_MAX);
        else
            mydata_next();
    } else if (p[0] == HIST_OLDER) {
        more_history = p[1];
        if (more_history)
            say("%s(older messages: /more)%s", col("\033[2m"), col("\033[0m"));
    }
}

static void on_pending(const uint8_t *p, size_t n)
{
    char name[HUSH_NAME_MAX + 1], fp[HUSH_FP_LEN];
    int k = n >= 1 ? name_get(p + 1, n - 1, name) : -1;
    if (k < 0 || n - 1 - (size_t)k != crypto_sign_PUBLICKEYBYTES)
        return;
    size_t i = 0;
    while (i < nwaiting && strcmp(waiting[i], name))
        i++;
    if (!p[0]) { /* decided */
        if (i < nwaiting)
            memmove(waiting[i], waiting[i + 1], (--nwaiting - i) * sizeof *waiting);
        return;
    }
    if (i == nwaiting && nwaiting < WAITING_MAX)
        strcpy(waiting[nwaiting++], name);
    fingerprint(p + 1 + k, fp);
    say("%s* %s wants to join, with fingerprint %s%s\n"
        "  If that's who you think, /approve %s, otherwise /deny %s",
        col("\033[1;33m"), name, fp, col("\033[0m"), name, name);
}

static void cmd_decide(const char *name, int approve)
{
    if (!am_admin) {
        say("! only an admin can do that");
        return;
    }
    if (!*name) {
        say("usage: /%s NAME", approve ? "approve" : "deny");
        return;
    }
    struct buf b = { 0 };
    uint8_t a = (uint8_t)approve;
    buf_put(&b, &a, 1);
    name_put(&b, name);
    if (name_valid(name, strlen(name)))
        net_send(T_DECIDE, &b);
    else
        say("! %s isn't a name", name);
    buf_free(&b);
}

static void cmd_newchat(const char *label)
{
    if (!am_admin) {
        say("! only an admin can create chats");
        return;
    }
    if (!name_valid(label, strlen(label))) {
        say("usage: /newchat NAME   (1-24 of A-Z a-z 0-9 _ . -)");
        return;
    }
    /* Key is made here. The server only gets its login token. */
    uint8_t tok[32];
    chat_key_new(new_key);
    if (chat_key_derive(new_key, strlen(new_key), tok, NULL) != 0) {
        say("! not enough memory to make a key");
        return;
    }
    strcpy(new_label, label);
    struct buf b = { 0 };
    name_put(&b, label);
    buf_put(&b, tok, sizeof tok);
    net_send(T_NEWCHAT, &b);
    buf_free(&b);
}

static void on_created(const uint8_t *p, size_t n)
{
    char label[HUSH_NAME_MAX + 1];
    if (name_get(p, n, label) < 0 || strcmp(label, new_label))
        return;
    say("%sCreated the chat \"%s\". Its key: %s%s\n"
        "  Give it to the people you want in there. It isn't stored anywhere, so keep it.",
        col("\033[1;32m"), label, new_key, col("\033[0m"));
    sodium_memzero(new_key, sizeof new_key);
    new_label[0] = '\0';
}

static void cmd_waiting(void)
{
    if (!am_admin) {
        say("! only an admin can see the waitlist");
        return;
    }
    if (!nwaiting)
        say("nobody is waiting to join");
    for (size_t i = 0; i < nwaiting; i++)
        say("  %s is waiting: /approve %s or /deny %s", waiting[i], waiting[i], waiting[i]);
}

/* Drop metadata (EXIF with the GPS position, XMP, comments) before an image
 * leaves this machine. Each returns the new length. */
static size_t strip_jpeg(uint8_t *d, size_t n)
{
    size_t i = 2, o = 2;
    while (i + 4 <= n && d[i] == 0xFF && d[i + 1] != 0xDA && d[i + 1] != 0xFF) {
        uint8_t m = d[i + 1];
        if (m == 0x01 || (m >= 0xD0 && m <= 0xD8)) { /* markers without a length */
            memmove(d + o, d + i, 2);
            o += 2, i += 2;
            continue;
        }
        size_t len = (size_t)d[i + 2] << 8 | d[i + 3];
        if (len < 2 || len > n - i - 2)
            break;
        if (m != 0xE1 && m != 0xED && m != 0xFE) { /* APP1 EXIF/XMP, APP13 IPTC, comment */
            memmove(d + o, d + i, 2 + len);
            o += 2 + len;
        }
        i += 2 + len;
    }
    memmove(d + o, d + i, n - i);
    return o + n - i;
}

static size_t strip_png(uint8_t *d, size_t n)
{
    static const char *const drop[] = { "eXIf", "tEXt", "zTXt", "iTXt", "tIME" };
    size_t i = 8, o = 8;
    while (i + 12 <= n) {
        uint32_t len = get_u32(d + i);
        if (len > n - i - 12)
            break;
        int keep = 1;
        for (size_t j = 0; j < sizeof drop / sizeof *drop; j++)
            keep &= memcmp(d + i + 4, drop[j], 4) != 0;
        if (keep) {
            memmove(d + o, d + i, 12 + (size_t)len);
            o += 12 + len;
        }
        i += 12 + len;
    }
    memmove(d + o, d + i, n - i);
    return o + n - i;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static size_t strip_webp(uint8_t *d, size_t n)
{
    size_t i = 12, o = 12;
    while (i + 8 <= n) {
        uint32_t len = le32(d + i + 4);
        if (len > n - i - 8 || len + (len & 1) > n - i - 8)
            break;
        size_t full = 8 + len + (len & 1);
        if (!memcmp(d + i, "VP8X", 4) && len >= 1)
            d[i + 8] &= (uint8_t)~0x0C; /* no EXIF or XMP chunks follow */
        if (memcmp(d + i, "EXIF", 4) && memcmp(d + i, "XMP ", 4)) {
            memmove(d + o, d + i, full);
            o += full;
        }
        i += full;
    }
    memmove(d + o, d + i, n - i);
    o += n - i;
    uint32_t riff = (uint32_t)(o - 8);
    for (int j = 0; j < 4; j++)
        d[4 + j] = (uint8_t)(riff >> (8 * j));
    return o;
}

/* Work out the type and size, and strip metadata. Returns -1 if it isn't a supported image. */
static int image_prepare(uint8_t *d, size_t *n, char mime[32], uint16_t *w, uint16_t *h)
{
    *w = *h = 0;
    if (*n > 12 && d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF) {
        strcpy(mime, "image/jpeg");
        *n = strip_jpeg(d, *n);
        for (size_t i = 2; i + 9 < *n && d[i] == 0xFF;) {
            uint8_t m = d[i + 1];
            if (m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC) {
                *h = get_u16(d + i + 5);
                *w = get_u16(d + i + 7);
                break;
            }
            if (m == 0xDA)
                break;
            i += 2 + ((size_t)d[i + 2] << 8 | d[i + 3]);
        }
    } else if (*n > 24 && !memcmp(d, "\x89PNG\r\n\x1a\n", 8)) {
        strcpy(mime, "image/png");
        uint32_t pw = get_u32(d + 16), ph = get_u32(d + 20);
        *w = pw > 65535 ? 65535 : (uint16_t)pw;
        *h = ph > 65535 ? 65535 : (uint16_t)ph;
        *n = strip_png(d, *n);
    } else if (*n > 10 && (!memcmp(d, "GIF87a", 6) || !memcmp(d, "GIF89a", 6))) {
        strcpy(mime, "image/gif");
        *w = (uint16_t)(d[6] | d[7] << 8);
        *h = (uint16_t)(d[8] | d[9] << 8);
    } else if (*n > 16 && !memcmp(d, "RIFF", 4) && !memcmp(d + 8, "WEBP", 4)) {
        strcpy(mime, "image/webp");
        *n = strip_webp(d, *n);
    } else {
        return -1;
    }
    return 0;
}

static void cmd_img(char *arg)
{
    if (upload.active) {
        say("! wait for the image you're sending to finish");
        return;
    }
    char *caption = strchr(arg, ' ');
    if (caption) {
        *caption++ = '\0';
        caption += strspn(caption, " ");
    }
    if (!*arg) {
        say("usage: /img FILE [caption]   (jpeg, png, gif or webp, up to 25 MB)");
        return;
    }
    FILE *f = fopen(arg, "rb");
    if (!f) {
        say("! cannot open %s: %s", arg, strerror(errno));
        return;
    }
    struct buf img = { 0 };
    size_t r;
    do {
        buf_reserve(&img, 1 << 20);
        r = fread(img.data + img.len, 1, img.cap - img.len, f);
        img.len += r;
    } while (r > 0 && !feof(f) && !ferror(f) && img.len <= HUSH_MAX_IMAGE);
    int bad = ferror(f);
    fclose(f);
    if (bad) {
        say("! cannot read %s", arg);
        buf_free(&img);
        return;
    }
    if (img.len > HUSH_MAX_IMAGE) {
        say("! %s is too big (25 MB at most)", arg);
        buf_free(&img);
        return;
    }
    if (image_prepare(img.data, &img.len, upload.mime, &upload.w, &upload.h) < 0) {
        say("! %s isn't a jpeg, png, gif or webp image", arg);
        buf_free(&img);
        return;
    }
    if (caption && strlen(caption) > HUSH_MAX_TEXT - 100)
        caption[HUSH_MAX_TEXT - 100] = '\0';
    snprintf(upload.caption, sizeof upload.caption, "%s", caption ? caption : "");
    upload.size = (uint32_t)img.len;
    crypto_aead_xchacha20poly1305_ietf_keygen(upload.file_key);

    /* nonce | ciphertext, sent in pieces */
    struct buf enc = { 0 };
    unsigned long long cl;
    buf_reserve(&enc, NONCE + img.len + MAC);
    randombytes_buf(enc.data, NONCE);
    crypto_aead_xchacha20poly1305_ietf_encrypt(enc.data + NONCE, &cl, img.data, img.len, NULL, 0, NULL,
                                               enc.data, upload.file_key);
    enc.len = NONCE + (size_t)cl;
    buf_free(&img);
    upload.active = 1;
    say("sending %s (%.1f MB)...", arg, (double)enc.len / 1048576.0);
    uint8_t piece[1 + HUSH_CHUNK];
    for (size_t off = 0; off < enc.len && running;) {
        size_t n = enc.len - off < HUSH_CHUNK ? enc.len - off : HUSH_CHUNK;
        piece[0] = (uint8_t)((off == 0 ? UP_FIRST : 0) | (off + n == enc.len ? UP_LAST : 0));
        memcpy(piece + 1, enc.data + off, n);
        net_send_raw(T_UPLOAD, piece, 1 + n);
        off += n;
    }
    buf_free(&enc);
}

static void on_uploaded(const uint8_t *p, size_t n)
{
    if (!upload.active || n != HUSH_BLOB_ID)
        return;
    struct buf c = { 0 };
    uint8_t meta[4 + 2 + 2 + 1];
    buf_put(&c, upload.file_key, 32);
    buf_put(&c, p, HUSH_BLOB_ID);
    put_u32(meta, upload.size);
    put_u16(meta + 4, upload.w);
    put_u16(meta + 6, upload.h);
    meta[8] = (uint8_t)strlen(upload.mime);
    buf_put(&c, meta, sizeof meta);
    buf_put(&c, upload.mime, meta[8]);
    buf_put(&c, upload.caption, strlen(upload.caption));
    post(NULL, KIND_IMAGE, c.data, c.len);
    sodium_memzero(c.data, c.len);
    buf_free(&c);
    sodium_memzero(&upload, sizeof upload);
}

static void cmd_save(const char *arg)
{
    char *end;
    unsigned long long id = strtoull(arg, &end, 10);
    struct image *im = NULL;
    for (size_t i = 0; i < IMAGES_MAX && id && !*end; i++)
        if (images[i].msg_id == id)
            im = &images[i];
    if (!im) {
        say("usage: /save N, with N from an [image ...] line");
        return;
    }
    if (download.active || mydata.active) {
        say("! wait for the download that's running to finish");
        return;
    }
    start_download(im, NULL, 0);
}

static void save_image(const uint8_t *img, size_t n)
{
    char dir[4096], path[4300];
    int fd = -1;
    if (*download.path) {
        snprintf(path, sizeof path, "%s", download.path);
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    } else {
        const char *home = getenv("HOME");
        struct stat st;
        snprintf(dir, sizeof dir, "%s/Downloads", home ? home : ".");
        if (!home || stat(dir, &st) < 0 || !S_ISDIR(st.st_mode))
            strcpy(dir, ".");
        const char *ext = image_ext(download.img.mime);
        for (int i = 0; i < 100 && fd < 0; i++) {
            if (i)
                snprintf(path, sizeof path, "%s/hush-%llu-%d.%s", dir, (unsigned long long)download.img.msg_id, i, ext);
            else
                snprintf(path, sizeof path, "%s/hush-%llu.%s", dir, (unsigned long long)download.img.msg_id, ext);
            fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        }
    }
    if (fd < 0 || write(fd, img, n) != (ssize_t)n || close(fd) < 0)
        say("! cannot save %s: %s", path, strerror(errno));
    else if (!download.for_mydata)
        say("saved %s", path);
}

static void download_done(void)
{
    download.active = 0;
    if (download.for_mydata)
        mydata_next();
}

static void on_blob(const uint8_t *p, size_t n)
{
    if (!download.active || n < HUSH_BLOB_ID + 1 || memcmp(p, download.img.blob, HUSH_BLOB_ID))
        return;
    int status = p[HUSH_BLOB_ID];
    if (status == BLOB_MISSING) {
        say("! the server doesn't have image %llu any more", (unsigned long long)download.img.msg_id);
        download_done();
        return;
    }
    buf_put(&download.data, p + HUSH_BLOB_ID + 1, n - HUSH_BLOB_ID - 1);
    if (download.data.len > HUSH_MAX_IMAGE + NONCE + MAC) {
        say("! image %llu is too big; not saved", (unsigned long long)download.img.msg_id);
        download_done();
        return;
    }
    if (status != BLOB_LAST)
        return;

    struct buf *d = &download.data;
    uint8_t *img = d->len >= NONCE + MAC ? malloc(d->len) : NULL;
    unsigned long long il;
    if (!img || crypto_aead_xchacha20poly1305_ietf_decrypt(img, &il, NULL, d->data + NONCE, d->len - NONCE,
                                                           NULL, 0, d->data, download.img.file_key) != 0)
        say("! image %llu failed to decrypt (tampered with?)", (unsigned long long)download.img.msg_id);
    else
        save_image(img, (size_t)il);
    free(img);
    download_done();
}

/* Handle every whole frame in rx. Also runs after the handshake, which may
 * have read frames past WELCOME. */
static void process_frames(void)
{
    uint8_t type;
    const uint8_t *p;
    size_t n, fs;
    int k;
    while ((k = frame_peek(&rx, &type, &p, &n, &fs)) == 1) {
        if (type == T_PEER)
            on_peer(p, n);
        else if (type == T_LEAVE)
            on_leave(p, n);
        else if (type == T_MSG)
            on_msg(p, n);
        else if (type == T_HISTORY_END)
            on_history_end(p, n);
        else if (type == T_UPLOADED)
            on_uploaded(p, n);
        else if (type == T_BLOB)
            on_blob(p, n);
        else if (type == T_PENDING)
            on_pending(p, n);
        else if (type == T_CREATED)
            on_created(p, n);
        else if (type == T_ERROR) {
            char msg[HUSH_MAX_FRAME + 1];
            sanitize(p, n, msg);
            say("! server: %s", msg);
            if (upload.active && strstr(msg, "image"))
                upload.active = 0;
        }
        buf_consume(&rx, fs);
    }
    if (k < 0) {
        say("! server sent a malformed frame, disconnecting");
        running = 0;
    }
}

static void on_net(void)
{
    buf_reserve(&rx, 65536);
    /* NOLINTNEXTLINE(clang-analyzer-unix.StdCLibraryFunctions): sock is open by now */
    ssize_t r = recv(sock, rx.data + rx.len, rx.cap - rx.len, 0);
    if (r < 0 && errno == EINTR)
        return;
    if (r <= 0) {
        say("! disconnected from the server");
        running = 0;
        return;
    }
    rx.len += (size_t)r;
    process_frames();
}

static void cmd_help(void)
{
    say("Type a message and press Enter to send it to everyone in the chat.\n"
        "  /msg NAME TEXT   private message to one person (they get it even if offline)\n"
        "  /img FILE [text] send an image (jpeg, png, gif or webp, up to 25 MB)\n"
        "  /save N          save image N to ~/Downloads\n"
        "  /more            show older messages\n"
        "  /mydata          save everything you sent, and DMs sent to you, to a folder\n"
        "  /who             who's in the chat, with fingerprints\n"
        "  /fp [NAME]       show your fingerprint, or NAME's\n"
        "  /verify NAME     mark NAME's key as verified after comparing fingerprints\n"
        "  /trust NAME      accept NAME's new key after it changed (verify it first!)\n"
        "  /quit            leave (also Ctrl-C)\n"
        "  //text           send a message that starts with /");
    if (am_admin)
        say("As an admin:\n"
            "  /waiting         who's waiting to join\n"
            "  /approve NAME    let NAME in (check their fingerprint first)\n"
            "  /deny NAME       turn NAME away\n"
            "  /newchat NAME    create a chat and get its key");
}

static void cmd_who(void)
{
    say("in %s:", chat_label);
    for (int pass = 1; pass >= 0; pass--) {
        for (size_t i = 0; i < npeers; i++) {
            struct peer *pe = &peers[i];
            if (pe->online != pass)
                continue;
            char fp[HUSH_FP_LEN];
            fingerprint(pe->pk, fp);
            struct known *kn = known_find(pe->name);
            const char *color, *label;
            if (pe->trust != TRUST_OK)
                color = "\033[1;31m", label = "KEY CHANGED";
            else if (kn && kn->verified)
                color = "\033[32m", label = "verified";
            else
                color = "\033[33m", label = "unverified";
            say("  %-12s  %s  %s%s%s%s", pe->name, fp, col(color), label, col("\033[0m"),
                pe->online ? "  online" : "");
        }
    }
    if (!npeers)
        say("  (just you so far)");
}

static void cmd_fp(const char *name)
{
    char fp[HUSH_FP_LEN];
    if (!*name) {
        fingerprint(my_pk, fp);
        say("your fingerprint: %s", fp);
        return;
    }
    struct peer *pe = peer_find(name);
    struct known *kn = known_find(name);
    if (!pe && !kn) {
        say("! never seen anyone called %s", name);
        return;
    }
    fingerprint(kn ? kn->pk : pe->pk, fp);
    say("%s: %s (%s)", name, fp, kn && kn->verified ? "verified" : "unverified");
    if (pe && pe->trust == TRUST_CHANGED) {
        fingerprint(pe->pk, fp);
        say("  their NEW key: %s", fp);
    }
}

static void cmd_verify(const char *name)
{
    struct known *kn = known_find(name);
    struct peer *pe = peer_find(name);
    if (!kn) {
        say("! never seen anyone called %s", name);
    } else if (pe && pe->trust != TRUST_OK) {
        say("! %s's key changed; confirm the new one and /trust %s first", name, name);
    } else {
        char fp[HUSH_FP_LEN];
        fingerprint(kn->pk, fp);
        kn->verified = 1;
        known_save();
        say("%s%s marked as verified (%s)%s", col("\033[32m"), name, fp, col("\033[0m"));
    }
}

static void cmd_trust(const char *name)
{
    struct peer *pe = peer_find(name);
    struct known *kn = known_find(name);
    if (!pe || !kn || pe->trust != TRUST_CHANGED) {
        say("! %s's key hasn't changed; nothing to do", name);
        return;
    }
    memcpy(kn->pk, pe->pk, sizeof kn->pk);
    kn->verified = 0;
    known_save();
    pe->trust = peer_derive(pe) == 0 ? TRUST_OK : TRUST_BAD;
    char fp[HUSH_FP_LEN];
    fingerprint(pe->pk, fp);
    say("accepted %s's new key %s (unverified)", name, fp);
}

static void cmd_msg(char *arg)
{
    char *text = strchr(arg, ' ');
    if (!text) {
        say("usage: /msg NAME TEXT");
        return;
    }
    *text++ = '\0';
    while (*text == ' ')
        text++;
    struct peer *pe = peer_find(arg);
    if (!pe) {
        say("! there is no %s in this chat", arg);
    } else if (pe->trust != TRUST_OK) {
        say("%s! not sent to %s: their key changed, see /help%s", col("\033[1;31m"), pe->name,
            col("\033[0m"));
    } else if (*text) {
        post(pe, KIND_TEXT, text, strlen(text));
    }
}

static void submit(void)
{
    char s[HUSH_MAX_TEXT + 1];
    while (line_len && line[line_len - 1] == ' ')
        line_len--;
    memcpy(s, line, line_len);
    s[line_len] = '\0';
    line_len = 0;
    if (!*s)
        return;

    if (s[0] == '/' && s[1] != '/') {
        char *cmd = s + 1, *arg = strchr(cmd, ' ');
        if (arg) {
            *arg++ = '\0';
            while (*arg == ' ')
                arg++;
        } else {
            arg = cmd + strlen(cmd);
        }
        if (!strcmp(cmd, "quit") || !strcmp(cmd, "q"))
            running = 0;
        else if (!strcmp(cmd, "help") || !strcmp(cmd, "h"))
            cmd_help();
        else if (!strcmp(cmd, "who") || !strcmp(cmd, "w"))
            cmd_who();
        else if (!strcmp(cmd, "msg") || !strcmp(cmd, "m"))
            cmd_msg(arg);
        else if (!strcmp(cmd, "img"))
            cmd_img(arg);
        else if (!strcmp(cmd, "save"))
            cmd_save(arg);
        else if (!strcmp(cmd, "mydata"))
            cmd_mydata();
        else if (!strcmp(cmd, "waiting"))
            cmd_waiting();
        else if (!strcmp(cmd, "newchat"))
            cmd_newchat(arg);
        else if (!strcmp(cmd, "approve"))
            cmd_decide(arg, 1);
        else if (!strcmp(cmd, "deny"))
            cmd_decide(arg, 0);
        else if (!strcmp(cmd, "more")) {
            if (mydata.active) {
                say("! wait for /mydata to finish");
            } else if (more_history && oldest_id) {
                say("%s--- older messages ---%s", col("\033[2m"), col("\033[0m"));
                request_history(0, oldest_id, HISTORY_PAGE);
            } else {
                say("(that's everything)");
            }
        } else if (!strcmp(cmd, "fp"))
            cmd_fp(arg);
        else if (!strcmp(cmd, "verify"))
            cmd_verify(arg);
        else if (!strcmp(cmd, "trust"))
            cmd_trust(arg);
        else
            say("! unknown command; try /help");
        return;
    }
    const char *text = s[0] == '/' ? s + 1 : s;
    post(NULL, KIND_TEXT, text, strlen(text));
}

static void on_key(uint8_t c)
{
    if (esc_state == 1) { /* swallow escape sequences (arrow keys etc.) */
        esc_state = (c == '[' || c == 'O') ? 2 : 0;
        return;
    }
    if (esc_state == 2) {
        if (c >= 0x40 && c <= 0x7e)
            esc_state = 0;
        return;
    }
    switch (c) {
    case 27:
        esc_state = 1;
        return;
    case 3: /* Ctrl-C */
        running = 0;
        return;
    case 4: /* Ctrl-D on an empty line */
        if (!line_len)
            running = 0;
        return;
    case '\r':
    case '\n':
        submit();
        break;
    case 127:
    case 8:
        if (line_len) {
            do
                line_len--;
            while (line_len && (line[line_len] & 0xC0) == 0x80);
        }
        break;
    case 21: /* Ctrl-U */
        line_len = 0;
        break;
    case 23: /* Ctrl-W */
        while (line_len && line[line_len - 1] == ' ')
            line_len--;
        while (line_len && line[line_len - 1] != ' ')
            line_len--;
        break;
    case 12: /* Ctrl-L */
        printf("\033[H\033[2J");
        break;
    default:
        if (c == '\t')
            c = ' ';
        if (c >= 0x20 && c != 0x7f && line_len < HUSH_MAX_TEXT)
            line[line_len++] = (char)c;
    }
    redraw();
}

static void on_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* Ask for the chat key on the terminal without echoing it. */
static void prompt_key(void)
{
    if (!isatty(STDIN_FILENO))
        die("no chat key: use -k KEY or set HUSH_KEY");
    struct termios t, off;
    int hide = tcgetattr(STDIN_FILENO, &t) == 0;
    fputs("chat key: ", stderr);
    if (hide) {
        off = t;
        off.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &off);
    }
    char *ok = fgets(chat_key_text, sizeof chat_key_text, stdin);
    if (hide)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    fputc('\n', stderr);
    if (!ok)
        die("no chat key given");
    chat_key_text[strcspn(chat_key_text, "\r\n")] = '\0'; /* NOLINT(clang-analyzer-security.ArrayBound) */
}

static void usage(void)
{
    fprintf(stderr, "usage: hush [-n name] [-k key] host[:port]   e.g.  hush -n alice 203.0.113.7\n"
                    "       hush [-n name] [-k key] host port\n"
                    "  -n name  your chat name (default: $USER)\n"
                    "  -k key   the chat key you were given (or set HUSH_KEY; asked for if missing)\n"
                    "  host     IP address or hostname of the machine running hushd\n"
                    "  port     defaults to " HUSH_DEFAULT_PORT "\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *name = getenv("USER"), *key = getenv("HUSH_KEY");
    int opt;
    while ((opt = getopt(argc, argv, "n:k:h")) != -1) {
        if (opt == 'n')
            name = optarg;
        else if (opt == 'k')
            key = optarg;
        else
            usage();
    }
    if (optind >= argc || argc - optind > 2)
        usage();
    /* Accept "host port", "host:port" and "[ipv6]:port". A bare IPv6
     * address has several colons and is taken as a host on its own. */
    static char host[NI_MAXHOST];
    const char *arg = argv[optind], *port = optind + 1 < argc ? argv[optind + 1] : NULL;
    const char *hp = NULL, *end = arg + strlen(arg);
    if (arg[0] == '[') {
        const char *rb = strchr(arg, ']');
        if (!rb || (rb[1] && rb[1] != ':'))
            die("bad address %s (use [ipv6]:port)", arg);
        hp = rb[1] ? rb + 2 : NULL;
        arg++, end = rb;
    } else if (strchr(arg, ':') && strchr(arg, ':') == strrchr(arg, ':')) {
        end = strchr(arg, ':');
        hp = end + 1;
    }
    if ((size_t)(end - arg) >= sizeof host || end == arg)
        die("bad address %s", argv[optind]);
    memcpy(host, arg, (size_t)(end - arg));
    if (hp && port)
        die("give the port once: either %s or a separate port argument", argv[optind]);
    if (hp)
        port = hp;
    if (!port)
        port = HUSH_DEFAULT_PORT;
    char *pe;
    long pn = strtol(port, &pe, 10);
    if (!*port || *pe || pn < 1 || pn > 65535)
        die("bad port \"%s\": it should be a number like " HUSH_DEFAULT_PORT
            " (usage: hush -n NAME HOST[:PORT])", port);
    if (!name || !name_valid(name, strlen(name)))
        die("pick a name with -n (1-24 of A-Z a-z 0-9 _ . -)");
    strcpy(my_name, name);

    if (sodium_init() < 0)
        die("libsodium failed to initialise");
    if (key && strlen(key) > HUSH_KEY_MAX)
        die("that chat key is too long");
    if (key && *key)
        strcpy(chat_key_text, key);
    else
        prompt_key();
    int bad = chat_key_derive(chat_key_text, strlen(chat_key_text), token, chat_key);
    if (bad == -2)
        die("not enough memory to read the chat key (Argon2id needs 128 MB)");
    if (bad)
        die("that isn't a chat key (it looks like xxxx-xxxx)");
    sodium_memzero(chat_key_text, sizeof chat_key_text);
    crypto_generichash(chat_id, sizeof chat_id, chat_key, sizeof chat_key, NULL, 0);

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa = { .sa_handler = on_signal };
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    char dir[4096];
    const char *xdg = getenv("XDG_DATA_HOME"), *home = getenv("HOME");
    if (xdg && *xdg)
        snprintf(dir, sizeof dir, "%s/hush", xdg);
    else if (home)
        snprintf(dir, sizeof dir, "%s/.local/share/hush", home);
    else
        die("HOME is not set");
    mkdir_p(dir);
    identity_load(dir);
    snprintf(known_path, sizeof known_path, "%s/known_peers", dir);
    known_load();

    sock = dial(host, port);
    handshake();

    interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    char fp[HUSH_FP_LEN];
    fingerprint(my_pk, fp);
    say("%sconnected to %s:%s as %s, chat: %s%s\nyour fingerprint: %s\ntype /help for commands%s",
        col("\033[1m"), host, port, my_name, chat_label, col("\033[0m"), fp,
        am_admin ? "\nyou're an admin: people who want to join show up here" : "");
    if (interactive)
        term_raw();
    ui_ready = 1;
    redraw();
    process_frames();
    request_history(0, 0, HISTORY_PAGE);

    struct pollfd pfd[2] = { { .fd = sock, .events = POLLIN }, { .fd = STDIN_FILENO, .events = POLLIN } };
    while (running) {
        if (poll(pfd, 2, -1) < 0) {
            if (errno == EINTR)
                continue;
            die("poll: %s", strerror(errno));
        }
        if (pfd[0].revents)
            on_net();
        if (running && pfd[1].revents) {
            uint8_t in[512];
            ssize_t r = read(STDIN_FILENO, in, sizeof in);
            if (r <= 0) {
                if (r < 0 && errno == EINTR)
                    continue;
                running = 0;
            }
            for (ssize_t i = 0; i < r && running; i++)
                on_key(in[i]);
        }
    }
    term_restore();
    close(sock);
    return 0;
}
