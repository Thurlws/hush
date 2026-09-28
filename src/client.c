/* hush: end-to-end encrypted terminal chat client.
 *
 * Identity: one ed25519 keypair per user (~/.local/share/hush/identity.key).
 * It signs the server's login challenge and, converted to X25519, is used
 * with crypto_box to encrypt every message separately for each recipient.
 *
 * Trust: the first key seen for a name is pinned in known_peers. A later
 * different key is refused until the user runs /trust. Comparing
 * fingerprints out of band (/fp, /verify) rules out a lying server. */
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

#define MAX_TEXT  4000
#define MAX_PEERS 256
/* Plaintext: u8 kind | u64 counter | u8 len | sender name | text.
 * The pairwise key is the same in both directions, so the sender's name is
 * sealed inside; otherwise the server could bounce your own message back
 * to you as if the other person had said it. */
#define PLAIN_MIN 10
#define PLAIN_MAX (PLAIN_MIN + HUSH_NAME_MAX + MAX_TEXT)
#define BLOB_OVERHEAD (crypto_box_NONCEBYTES + crypto_box_MACBYTES)

enum { KIND_ROOM = 0, KIND_DM = 1 };
enum { TRUST_OK, TRUST_CHANGED, TRUST_BAD };

struct known {
    char name[HUSH_NAME_MAX + 1];
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    int verified;
};

struct peer {
    char name[HUSH_NAME_MAX + 1];
    uint8_t pk[crypto_sign_PUBLICKEYBYTES]; /* key the server announced */
    uint8_t key[crypto_box_BEFORENMBYTES];  /* precomputed shared key */
    int online, trust;
    uint64_t last_ctr; /* highest counter seen, to reject replays */
};

static struct known *known;
static size_t nknown;
static char known_path[4200];
static struct peer peers[MAX_PEERS];
static size_t npeers;

static char my_name[HUSH_NAME_MAX + 1];
static char chat_key[HUSH_KEY_MAX + 2], chat_label[HUSH_NAME_MAX + 1];
static uint8_t my_pk[crypto_sign_PUBLICKEYBYTES], my_sk[crypto_sign_SECRETKEYBYTES];
static uint8_t my_xsk[crypto_scalarmult_BYTES];
static uint64_t my_ctr;

static int sock = -1;
static struct buf rx, tx;
static int interactive, ui_ready;
static volatile sig_atomic_t running = 1;
static struct termios orig_tio;
static int raw_on;
static char line[MAX_TEXT + 1];
static size_t line_len;
static int esc_state;

/* ---- terminal ---------------------------------------------------------- */

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
    t.c_iflag &= ~(ICRNL | IXON | BRKINT | ISTRIP | INPCK);
    t.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    raw_on = 1;
    atexit(term_restore);
}

/* Copy untrusted text for display, dropping anything a terminal could
 * interpret: C0/C1 control codes (escape sequences) and invalid UTF-8.
 * dst must hold n + 1 bytes. */
static void sanitize(const uint8_t *s, size_t n, char *dst)
{
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        uint8_t c = s[i];
        if (c < 0x80) {
            dst[o++] = c >= 0x20 && c != 0x7f ? (char)c : (c == '\t' || c == '\n') ? ' ' : '?';
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
    return 31 + h % 6;
}

static void show_msg(const char *from, const char *tag, const uint8_t *text, size_t n)
{
    char ts[8], clean[MAX_TEXT + 1], color[16];
    time_t t = time(NULL);
    strftime(ts, sizeof ts, "%H:%M", localtime(&t));
    sanitize(text, n > MAX_TEXT ? MAX_TEXT : n, clean);
    snprintf(color, sizeof color, "\033[1;%dm", name_color(from));
    say("%s%s%s %s%s%s%s: %s", col("\033[2m"), ts, col("\033[0m"), tag, col(color), from,
        col("\033[0m"), clean);
}

/* ---- identity and pinned keys ------------------------------------------ */

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

/* ---- network ------------------------------------------------------------ */

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

static void net_send(uint8_t type, const struct buf *payload)
{
    tx.len = 0;
    frame_put(&tx, type, payload->data, payload->len);
    for (size_t off = 0; off < tx.len;) {
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

    uint8_t kl = (uint8_t)strlen(chat_key);
    name_put(&b, my_name);
    buf_put(&b, my_pk, sizeof my_pk);
    buf_put(&b, &kl, 1);
    buf_put(&b, chat_key, kl);
    net_send(T_HELLO, &b);
    sodium_memzero(b.data, b.len);
    sodium_memzero(chat_key, sizeof chat_key);

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

    expect(T_WELCOME, &p, &n, &fs);
    if (name_get(p, n, chat_label) < 0)
        die("bad welcome from server");
    buf_consume(&rx, fs);
}

/* ---- peers and messages -------------------------------------------------- */

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

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

/* Encrypt text for every online trusted peer (or just `only`). Returns how
 * many copies were sent. */
static int send_text(int kind, const struct peer *only, const char *text)
{
    size_t tl = strlen(text), nl = strlen(my_name), pl = PLAIN_MIN + nl + tl;
    uint8_t plain[PLAIN_MAX], blob[BLOB_OVERHEAD + PLAIN_MAX];
    uint64_t now = now_us();
    my_ctr = now > my_ctr ? now : my_ctr + 1;
    plain[0] = (uint8_t)kind;
    put_u64(plain + 1, my_ctr);
    plain[9] = (uint8_t)nl;
    memcpy(plain + PLAIN_MIN, my_name, nl);
    memcpy(plain + PLAIN_MIN + nl, text, tl);

    int sent = 0;
    struct buf b = { 0 };
    for (size_t i = 0; i < npeers && running; i++) {
        struct peer *pe = &peers[i];
        if ((only && pe != only) || !pe->online)
            continue;
        if (pe->trust != TRUST_OK) {
            say("%s! not sent to %s: their key changed, see /help trust%s", col("\033[1;31m"),
                pe->name, col("\033[0m"));
            continue;
        }
        randombytes_buf(blob, crypto_box_NONCEBYTES);
        crypto_box_easy_afternm(blob + crypto_box_NONCEBYTES, plain, pl, blob, pe->key);
        b.len = 0;
        name_put(&b, pe->name);
        buf_put(&b, blob, BLOB_OVERHEAD + pl);
        net_send(T_SEND, &b);
        sent++;
    }
    buf_free(&b);
    sodium_memzero(plain, sizeof plain);
    return sent;
}

static void on_peer(const uint8_t *p, size_t n)
{
    char name[HUSH_NAME_MAX + 1], fp[HUSH_FP_LEN], oldfp[HUSH_FP_LEN];
    int k = name_get(p, n, name);
    if (k < 0 || n - k != crypto_sign_PUBLICKEYBYTES + 1 || !strcmp(name, my_name))
        return;
    const uint8_t *pk = p + k;
    int joined = p[k + crypto_sign_PUBLICKEYBYTES];

    struct peer *pe = peer_find(name);
    if (!pe) {
        if (npeers == MAX_PEERS)
            return;
        pe = &peers[npeers++];
        memset(pe, 0, sizeof *pe);
        strcpy(pe->name, name);
    }
    memcpy(pe->pk, pk, sizeof pe->pk);
    pe->online = 1;
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

    const char *what = joined ? "joined" : "is here";
    if (pe->trust == TRUST_BAD) {
        say("%s! %s presented an invalid key; ignoring them%s", col("\033[1;31m"), name, col("\033[0m"));
    } else if (pe->trust == TRUST_CHANGED) {
        fingerprint(kn->pk, oldfp);
        say("%s!!! WARNING: %s's key has CHANGED !!!%s\n"
            "    Either they reset their identity, or someone (the server?) is trying to\n"
            "    read your messages. Nothing will be sent to or accepted from them.\n"
            "    pinned: %s\n    now:    %s\n"
            "    Call them, compare the new fingerprint, then run /trust %s",
            col("\033[1;31m"), name, col("\033[0m"), oldfp, fp, name);
    } else if (first) {
        say("%s* %s %s%s. First time seeing them: fingerprint %s%s%s\n"
            "  Compare it with them on another channel (e.g. a call), then run /verify %s",
            col("\033[33m"), name, what, col("\033[0m"), col("\033[1m"), fp, col("\033[0m"), name);
    } else {
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
    say("%s* %s left%s", col("\033[33m"), name, col("\033[0m"));
}

static void on_deliver(const uint8_t *p, size_t n)
{
    char name[HUSH_NAME_MAX + 1];
    int k = name_get(p, n, name);
    if (k < 0)
        return;
    const uint8_t *blob = p + k;
    size_t bl = n - (size_t)k;

    struct peer *pe = peer_find(name);
    if (!pe || pe->trust != TRUST_OK) {
        say("! dropped a message from %s (key not trusted)", name);
        return;
    }
    if (bl < BLOB_OVERHEAD + PLAIN_MIN || bl > BLOB_OVERHEAD + PLAIN_MAX) {
        say("! dropped a malformed message from %s", name);
        return;
    }
    uint8_t plain[PLAIN_MAX];
    size_t pl = bl - BLOB_OVERHEAD;
    if (crypto_box_open_easy_afternm(plain, blob + crypto_box_NONCEBYTES,
                                     bl - crypto_box_NONCEBYTES, blob, pe->key) != 0) {
        say("! a message from %s failed to decrypt (tampered with?)", name);
        return;
    }
    uint64_t ctr = get_u64(plain + 1);
    size_t nl = plain[9], hdr = PLAIN_MIN + nl;
    if (hdr > pl || nl != strlen(name) || memcmp(plain + PLAIN_MIN, name, nl) != 0) {
        say("! dropped a message relabelled as coming from %s", name);
    } else if (ctr <= pe->last_ctr) {
        say("! dropped a replayed message from %s", name);
    } else {
        pe->last_ctr = ctr;
        if (plain[0] == KIND_DM) {
            char tag[32];
            snprintf(tag, sizeof tag, "%s[dm]%s ", col("\033[35m"), col("\033[0m"));
            show_msg(name, tag, plain + hdr, pl - hdr);
        } else {
            show_msg(name, "", plain + hdr, pl - hdr);
        }
    }
    sodium_memzero(plain, sizeof plain);
}

/* Handle every whole frame in rx. Also called right after the handshake,
 * which may have read the initial PEER frames along with WELCOME. */
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
        else if (type == T_DELIVER)
            on_deliver(p, n);
        else if (type == T_ERROR) {
            char msg[HUSH_MAX_FRAME + 1];
            sanitize(p, n, msg);
            say("! server: %s", msg);
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
    buf_reserve(&rx, 16384);
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

/* ---- commands ------------------------------------------------------------ */

static void cmd_help(void)
{
    say("Type a message and press Enter to send it to everyone online.\n"
        "  /msg NAME TEXT   private message to one person\n"
        "  /who             who's online, with fingerprints\n"
        "  /fp [NAME]       show your fingerprint, or NAME's\n"
        "  /verify NAME     mark NAME's key as verified after comparing fingerprints\n"
        "  /trust NAME      accept NAME's new key after it changed (verify it first!)\n"
        "  /quit            leave (also Ctrl-C)\n"
        "  //text           send a message that starts with /");
}

static void cmd_who(void)
{
    int any = 0;
    say("online:");
    for (size_t i = 0; i < npeers; i++) {
        struct peer *pe = &peers[i];
        if (!pe->online)
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
        say("  %-12s  %s  %s%s%s", pe->name, fp, col(color), label, col("\033[0m"));
        any = 1;
    }
    if (!any)
        say("  (just you)");
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
    pe->last_ctr = 0;
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
    if (!pe || !pe->online) {
        say("! %s is not online", arg);
        return;
    }
    if (*text && send_text(KIND_DM, pe, text) > 0) {
        char tag[64];
        snprintf(tag, sizeof tag, "%s[dm to %s]%s ", col("\033[35m"), pe->name, col("\033[0m"));
        show_msg(my_name, tag, (const uint8_t *)text, strlen(text));
    }
}

static void submit(void)
{
    char s[MAX_TEXT + 1];
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
        else if (!strcmp(cmd, "fp"))
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
    int anyone = 0;
    for (size_t i = 0; i < npeers; i++)
        anyone |= peers[i].online;
    if (send_text(KIND_ROOM, NULL, text) > 0)
        show_msg(my_name, "", (const uint8_t *)text, strlen(text));
    else if (running && !anyone)
        say("(message not sent: nobody else is here)");
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
        if (c >= 0x20 && c != 0x7f && line_len < MAX_TEXT)
            line[line_len++] = (char)c;
    }
    redraw();
}

/* ---- main ---------------------------------------------------------------- */

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
    char *ok = fgets(chat_key, sizeof chat_key, stdin);
    if (hide)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    fputc('\n', stderr);
    if (!ok)
        die("no chat key given");
    chat_key[strcspn(chat_key, "\r\n")] = '\0';
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
    if (key && strlen(key) > HUSH_KEY_MAX)
        die("that chat key is too long");
    if (key && *key)
        strcpy(chat_key, key);
    else
        prompt_key();
    if (!*chat_key || strlen(chat_key) > HUSH_KEY_MAX)
        die("that chat key is not valid");

    if (sodium_init() < 0)
        die("libsodium failed to initialise");
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
    say("%sconnected to %s:%s as %s, chat: %s%s\nyour fingerprint: %s\ntype /help for commands",
        col("\033[1m"), host, port, my_name, chat_label, col("\033[0m"), fp);
    if (interactive)
        term_raw();
    ui_ready = 1;
    redraw();
    process_frames();

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
