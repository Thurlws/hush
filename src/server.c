/* hushd: relay server. It authenticates users by their signing key, lets
 * them into a chat only with a key the admin created, and forwards
 * encrypted blobs between people in the same chat. It never holds a key
 * that can decrypt messages. It also serves the web client, which speaks
 * the same protocol over a WebSocket. */
#include "proto.h"
#include "web.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS  512
#define MAX_OUTBUF   (4u << 20)
#define AUTH_TIMEOUT 15 /* seconds a connection may spend in the handshake */
#define HTTP_TIMEOUT 10 /* ... sending its HTTP request */
#define SEND_TIMEOUT 60 /* ... downloading a response */

/* Per-address limits. IPv6 addresses count per /64, since one machine
 * usually has a whole /64 to pick from. */
#define IP_CONNS   16         /* open connections */
#define CONN_BURST 30.0       /* new connections and HTTP requests ... */
#define CONN_RATE  0.5        /* ... refilled per second */
#define AUTH_BURST 5.0        /* wrong chat keys ... */
#define AUTH_RATE  (1.0 / 60) /* ... refilled per second */
/* Per connection. Each copy of a message counts, one per recipient. */
#define MSG_BURST 300.0
#define MSG_RATE  50.0

/* Chat keys: 24 characters of Crockford base32, 120 random bits. */
#define KEY_CHARS 24
static const char key_alphabet[] = "0123456789abcdefghjkmnpqrstvwxyz";

enum cstate { ST_HTTP, ST_HELLO, ST_AUTH, ST_READY };

struct client {
    int fd;
    enum cstate st;
    int ws;       /* speaks WebSocket (web client) */
    int proxied;  /* came through a trusted local reverse proxy */
    int counted;  /* holds one of its address's connection slots */
    int dead, closing;
    int refused;     /* dropped with an error; web clients shouldn't reconnect */
    time_t deadline; /* drop the connection after this; 0 for never */
    uint8_t ip[16];  /* rate-limit key */
    char addr[INET6_ADDRSTRLEN];
    char name[HUSH_NAME_MAX + 1];
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t challenge[HUSH_CHALLENGE_LEN];
    uint8_t room[crypto_generichash_BYTES];
    double msg_tokens, msg_t;
    struct buf in, out;
};

/* Names are pinned to the first key that claims them, so nobody can take
 * over a friend's name on this server. */
struct user {
    char name[HUSH_NAME_MAX + 1];
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
};

/* A chat, known only by the hash of its key. */
struct room {
    uint8_t hash[crypto_generichash_BYTES];
    char label[HUSH_NAME_MAX + 1];
};

struct limit {
    uint8_t ip[16];
    int used, conns;
    double conn, auth, t;
};

static struct client *clients[MAX_CLIENTS];
static struct user *users;
static size_t nusers;
static struct room *rooms;
static size_t nrooms;
static const char *users_path = "hushd-users.txt", *keys_path = "hushd-keys.txt";
static struct stat users_st, keys_st;
static int trust_proxy;

#define LIMIT_SLOTS 4096
#define LIMIT_PROBE 8
static struct limit limits[LIMIT_SLOTS];

__attribute__((format(printf, 1, 2))) static void note(const char *fmt, ...)
{
    char ts[32];
    time_t t = time(NULL);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", localtime(&t));
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s ", ts);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static double now_mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static double refill(double tokens, double burst, double rate, double dt)
{
    tokens += dt * rate;
    return tokens > burst ? burst : tokens;
}

/* ---- addresses and rate limits ---------------------------------------------- */

static void sa_to_in6(const struct sockaddr_storage *ss, struct in6_addr *a)
{
    memset(a, 0, sizeof *a);
    if (ss->ss_family == AF_INET6) {
        *a = ((const struct sockaddr_in6 *)ss)->sin6_addr;
    } else if (ss->ss_family == AF_INET) {
        a->s6_addr[10] = a->s6_addr[11] = 0xff;
        memcpy(a->s6_addr + 12, &((const struct sockaddr_in *)ss)->sin_addr, 4);
    }
}

static int ip_parse(const char *s, struct in6_addr *a)
{
    struct in_addr v4;
    if (inet_pton(AF_INET, s, &v4) == 1) {
        memset(a, 0, sizeof *a);
        a->s6_addr[10] = a->s6_addr[11] = 0xff;
        memcpy(a->s6_addr + 12, &v4, 4);
        return 0;
    }
    return inet_pton(AF_INET6, s, a) == 1 ? 0 : -1;
}

static void ip_use(struct client *c, const struct in6_addr *a)
{
    memcpy(c->ip, a, sizeof c->ip);
    if (IN6_IS_ADDR_V4MAPPED(a))
        inet_ntop(AF_INET, a->s6_addr + 12, c->addr, sizeof c->addr);
    else {
        memset(c->ip + 8, 0, 8);
        inet_ntop(AF_INET6, a, c->addr, sizeof c->addr);
    }
}

static int ip_loopback(const struct in6_addr *a)
{
    return IN6_IS_ADDR_LOOPBACK(a) || (IN6_IS_ADDR_V4MAPPED(a) && a->s6_addr[12] == 127);
}

/* The (refilled) limits for an address. The table has a fixed size; when a
 * spot is needed, the entry idle the longest gives way. */
static struct limit *limit_get(const uint8_t ip[16])
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 16; i++)
        h = (h ^ ip[i]) * 16777619u;
    double now = now_mono();
    struct limit *l = NULL, *spare = NULL;
    for (int i = 0; i < LIMIT_PROBE && !l; i++) {
        struct limit *e = &limits[(h + i) % LIMIT_SLOTS];
        if (e->used && !memcmp(e->ip, ip, 16))
            l = e;
        else if (!spare || !e->used ||
                 (spare->used && (e->conns < spare->conns ||
                                  (e->conns == spare->conns && e->t < spare->t))))
            spare = e;
    }
    if (!l) {
        l = spare;
        memset(l, 0, sizeof *l);
        memcpy(l->ip, ip, 16);
        l->used = 1;
        l->conn = CONN_BURST;
        l->auth = AUTH_BURST;
    } else {
        l->conn = refill(l->conn, CONN_BURST, CONN_RATE, now - l->t);
        l->auth = refill(l->auth, AUTH_BURST, AUTH_RATE, now - l->t);
    }
    l->t = now;
    return l;
}

/* ---- users and chat keys ---------------------------------------------------- */

static struct user *user_find(const char *name)
{
    for (size_t i = 0; i < nusers; i++)
        if (!strcmp(users[i].name, name))
            return &users[i];
    return NULL;
}

static void user_add(const struct user *u)
{
    struct user *p = realloc(users, (nusers + 1) * sizeof *users);
    if (!p)
        die("out of memory");
    users = p;
    users[nusers++] = *u;
}

static void users_load(void)
{
    nusers = 0;
    FILE *f = fopen(users_path, "r");
    if (!f) {
        if (errno != ENOENT)
            die("cannot read %s: %s", users_path, strerror(errno));
        return;
    }
    char name[64], hex[128];
    while (fscanf(f, "%63s %127s", name, hex) == 2) {
        struct user u = { 0 };
        size_t bl;
        if (!name_valid(name, strlen(name)) ||
            sodium_hex2bin(u.pk, sizeof u.pk, hex, strlen(hex), NULL, &bl, NULL) != 0 ||
            bl != sizeof u.pk) {
            note("skipping bad line in %s", users_path);
            continue;
        }
        strcpy(u.name, name);
        user_add(&u);
    }
    fclose(f);
}

static void user_pin(const char *name, const uint8_t *pk)
{
    struct user u = { 0 };
    strcpy(u.name, name);
    memcpy(u.pk, pk, sizeof u.pk);
    user_add(&u);

    char hex[sizeof u.pk * 2 + 1];
    sodium_bin2hex(hex, sizeof hex, pk, sizeof u.pk);
    FILE *f = fopen(users_path, "a");
    if (!f || fprintf(f, "%s %s\n", name, hex) < 0 || fclose(f) != 0)
        note("warning: could not save %s to %s: %s", name, users_path, strerror(errno));
}

static struct room *room_find(const uint8_t *hash)
{
    for (size_t i = 0; i < nrooms; i++)
        if (!sodium_memcmp(rooms[i].hash, hash, sizeof rooms[i].hash))
            return &rooms[i];
    return NULL;
}

static struct room *room_by_label(const char *label)
{
    for (size_t i = 0; i < nrooms; i++)
        if (!strcmp(rooms[i].label, label))
            return &rooms[i];
    return NULL;
}

static void room_add(const struct room *r)
{
    struct room *p = realloc(rooms, (nrooms + 1) * sizeof *rooms);
    if (!p)
        die("out of memory");
    rooms = p;
    rooms[nrooms++] = *r;
}

static void keys_load(void)
{
    nrooms = 0;
    FILE *f = fopen(keys_path, "r");
    if (!f) {
        if (errno != ENOENT)
            note("cannot read %s: %s", keys_path, strerror(errno));
        return;
    }
    char hex[128], label[64];
    while (fscanf(f, "%127s %63s", hex, label) == 2) {
        struct room r = { 0 };
        size_t bl;
        if (!name_valid(label, strlen(label)) ||
            sodium_hex2bin(r.hash, sizeof r.hash, hex, strlen(hex), NULL, &bl, NULL) != 0 ||
            bl != sizeof r.hash) {
            note("skipping bad line in %s", keys_path);
            continue;
        }
        strcpy(r.label, label);
        room_add(&r);
    }
    fclose(f);
}

/* Replace path with the output of write_fn, atomically. */
static void file_replace(const char *path, void (*write_fn)(FILE *))
{
    char tmp[4200];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f)
        die("cannot write %s: %s", tmp, strerror(errno));
    write_fn(f);
    if (fflush(f) != 0 || fsync(fileno(f)) != 0 || fclose(f) != 0 || rename(tmp, path) != 0)
        die("cannot write %s: %s", path, strerror(errno));
}

static void keys_write(FILE *f)
{
    for (size_t i = 0; i < nrooms; i++) {
        char hex[sizeof rooms[i].hash * 2 + 1];
        sodium_bin2hex(hex, sizeof hex, rooms[i].hash, sizeof rooms[i].hash);
        fprintf(f, "%s %s\n", hex, rooms[i].label);
    }
}

static void users_write(FILE *f)
{
    for (size_t i = 0; i < nusers; i++) {
        char hex[sizeof users[i].pk * 2 + 1];
        sodium_bin2hex(hex, sizeof hex, users[i].pk, sizeof users[i].pk);
        fprintf(f, "%s %s\n", users[i].name, hex);
    }
}

/* Hash a chat key as typed: case, dashes and spaces don't matter, and
 * o/i/l are read as 0/1/1. Returns -1 if it can't be a key. */
static int key_hash(const uint8_t *s, size_t n, uint8_t out[crypto_generichash_BYTES])
{
    char norm[KEY_CHARS];
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        char ch = (char)tolower(s[i]);
        if (ch == '-' || ch == ' ')
            continue;
        if (ch == 'o')
            ch = '0';
        else if (ch == 'i' || ch == 'l')
            ch = '1';
        if (!ch || !strchr(key_alphabet, ch) || k == KEY_CHARS)
            return -1;
        norm[k++] = ch;
    }
    if (k != KEY_CHARS)
        return -1;
    static const char context[] = "hush-chat-key-v1";
    crypto_generichash(out, crypto_generichash_BYTES, (const uint8_t *)norm, k,
                       (const uint8_t *)context, sizeof context - 1);
    sodium_memzero(norm, sizeof norm);
    return 0;
}

static int file_changed(const char *path, struct stat *last)
{
    struct stat st;
    if (stat(path, &st) < 0)
        memset(&st, 0, sizeof st);
    int changed = st.st_ino != last->st_ino || st.st_size != last->st_size ||
                  st.st_mtim.tv_sec != last->st_mtim.tv_sec ||
                  st.st_mtim.tv_nsec != last->st_mtim.tv_nsec;
    *last = st;
    return changed;
}

/* ---- clients ------------------------------------------------------------------ */

static struct client *client_find(const char *name)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i] && !clients[i]->dead && clients[i]->st == ST_READY &&
            !strcmp(clients[i]->name, name))
            return clients[i];
    return NULL;
}

static int same_room(const struct client *a, const struct client *b)
{
    return !memcmp(a->room, b->room, sizeof a->room);
}

static void send_to(struct client *c, uint8_t type, const void *p, size_t n)
{
    if (c->dead || c->closing)
        return;
    if (c->ws)
        ws_put(&c->out, WS_BINARY, &type, 1, p, n);
    else
        frame_put(&c->out, type, p, n);
    if (c->out.len > MAX_OUTBUF) {
        note("%s: not reading its messages, dropping", c->addr);
        c->dead = 1;
    }
}

static void send_error(struct client *c, const char *msg, int fatal)
{
    send_to(c, T_ERROR, msg, strlen(msg));
    if (fatal)
        c->dead = c->refused = 1;
}

static void send_peer(struct client *to, const struct client *who, uint8_t joined)
{
    struct buf b = { 0 };
    name_put(&b, who->name);
    buf_put(&b, who->pk, sizeof who->pk);
    buf_put(&b, &joined, 1);
    send_to(to, T_PEER, b.data, b.len);
    buf_free(&b);
}

static void on_hello(struct client *c, const uint8_t *p, size_t n)
{
    int k = name_get(p, n, c->name);
    size_t kl;
    if (k < 0 || n - k < crypto_sign_PUBLICKEYBYTES + 1 ||
        (kl = p[k + crypto_sign_PUBLICKEYBYTES]) != n - k - crypto_sign_PUBLICKEYBYTES - 1) {
        send_error(c, "bad hello (names are 1-24 of A-Z a-z 0-9 _ . -)", 1);
        return;
    }
    /* Check the key before saying anything about names, so strangers learn nothing. */
    struct limit *l = limit_get(c->ip);
    if (l->auth < 1) {
        note("%s: too many wrong keys, refused", c->addr);
        send_error(c, "too many wrong keys from your address; wait a few minutes", 1);
        return;
    }
    if (key_hash(p + k + crypto_sign_PUBLICKEYBYTES + 1, kl, c->room) != 0 || !room_find(c->room)) {
        l->auth -= 1;
        note("%s: wrong key", c->addr);
        send_error(c, "wrong key", 1);
        return;
    }
    memcpy(c->pk, p + k, sizeof c->pk);
    struct user *u = user_find(c->name);
    if (u && sodium_memcmp(u->pk, c->pk, sizeof c->pk) != 0) {
        send_error(c, "that name is taken on this server (by another device or key)", 1);
        return;
    }
    randombytes_buf(c->challenge, sizeof c->challenge);
    send_to(c, T_CHALLENGE, c->challenge, sizeof c->challenge);
    c->st = ST_AUTH;
}

static void on_auth(struct client *c, const uint8_t *p, size_t n)
{
    uint8_t msg[sizeof HUSH_AUTH_CONTEXT - 1 + HUSH_CHALLENGE_LEN];
    memcpy(msg, HUSH_AUTH_CONTEXT, sizeof HUSH_AUTH_CONTEXT - 1);
    memcpy(msg + sizeof HUSH_AUTH_CONTEXT - 1, c->challenge, HUSH_CHALLENGE_LEN);
    if (n != crypto_sign_BYTES || crypto_sign_verify_detached(p, msg, sizeof msg, c->pk) != 0) {
        send_error(c, "authentication failed", 1);
        return;
    }
    const struct room *r = room_find(c->room);
    if (!r) {
        send_error(c, "this chat's key was revoked", 1);
        return;
    }
    if (client_find(c->name)) {
        send_error(c, "that name is already connected", 1);
        return;
    }
    if (!user_find(c->name)) {
        user_pin(c->name, c->pk);
        note("%s: registered new user %s", c->addr, c->name);
    }
    c->st = ST_READY;
    c->deadline = 0;
    c->msg_tokens = MSG_BURST;
    c->msg_t = now_mono();
    note("%s: %s joined %s", c->addr, c->name, r->label);

    struct buf b = { 0 };
    name_put(&b, r->label);
    send_to(c, T_WELCOME, b.data, b.len);
    buf_free(&b);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        struct client *o = clients[i];
        if (!o || o == c || o->dead || o->st != ST_READY || !same_room(o, c))
            continue;
        send_peer(c, o, 0);
        send_peer(o, c, 1);
    }
}

static void on_send(struct client *c, const uint8_t *p, size_t n)
{
    double now = now_mono();
    c->msg_tokens = refill(c->msg_tokens, MSG_BURST, MSG_RATE, now - c->msg_t);
    c->msg_t = now;
    if (c->msg_tokens < 1) {
        note("%s: %s is sending too fast, dropping", c->addr, c->name);
        send_error(c, "you are sending too fast", 1);
        return;
    }
    c->msg_tokens -= 1;

    char to[HUSH_NAME_MAX + 1];
    int k = name_get(p, n, to);
    if (k < 0 || n - k < crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
        send_error(c, "malformed message", 1);
        return;
    }
    struct client *dst = client_find(to);
    if (!dst || !same_room(dst, c)) {
        char msg[64 + HUSH_NAME_MAX];
        snprintf(msg, sizeof msg, "%s is not online", to);
        send_error(c, msg, 0);
        return;
    }
    struct buf b = { 0 };
    name_put(&b, c->name);
    buf_put(&b, p + k, n - k);
    send_to(dst, T_DELIVER, b.data, b.len);
    buf_free(&b);
}

static void handle_frame(struct client *c, uint8_t type, const uint8_t *p, size_t n)
{
    if (c->st == ST_HELLO && type == T_HELLO)
        on_hello(c, p, n);
    else if (c->st == ST_AUTH && type == T_AUTH)
        on_auth(c, p, n);
    else if (c->st == ST_READY && type == T_SEND)
        on_send(c, p, n);
    else
        send_error(c, "protocol violation", 1);
}

static void finish_http(struct client *c)
{
    c->closing = 1;
    c->deadline = time(NULL) + SEND_TIMEOUT;
    c->in.len = 0;
}

static void http_read(struct client *c)
{
    struct http_req req;
    int k = http_parse(c->in.data, c->in.len, &req);
    if (k == 0)
        return;
    if (k < 0) {
        http_error(&c->out, c->in.len >= HTTP_MAX_HEADER ? 431 : 400);
        finish_http(c);
        return;
    }
    int ws = !strcmp(req.path, "/ws");
    if (c->proxied) {
        /* The proxy appends the address it saw as the last X-Forwarded-For entry. */
        const char *last = strrchr(req.xff, ',');
        char ipstr[sizeof req.xff];
        snprintf(ipstr, sizeof ipstr, "%s", last ? last + 1 : req.xff);
        char *s = ipstr + strspn(ipstr, " \t");
        s[strcspn(s, " \t")] = '\0';
        struct in6_addr a;
        if (ip_parse(s, &a) == 0)
            ip_use(c, &a);
        struct limit *l = limit_get(c->ip);
        if (l->conn < 1 || (ws && l->conns >= IP_CONNS)) {
            http_error(&c->out, 429);
            finish_http(c);
            return;
        }
        l->conn -= 1;
        if (ws) {
            l->conns++;
            c->counted = 1;
        }
    }
    if (ws && ws_upgrade(&c->out, &req)) {
        c->ws = 1;
        c->st = ST_HELLO;
        c->deadline = time(NULL) + AUTH_TIMEOUT;
        buf_consume(&c->in, (size_t)k);
        return;
    }
    if (!ws)
        http_serve(&c->out, &req);
    finish_http(c);
}

static void ws_read(struct client *c)
{
    int op, k = 0;
    uint8_t *p;
    size_t n, fs;
    while (!c->dead && !c->closing &&
           (k = ws_peek(&c->in, &op, &p, &n, &fs, HUSH_MAX_FRAME)) == 1) {
        if (op == WS_BINARY && n >= 1) {
            handle_frame(c, p[0], p + 1, n - 1);
        } else if (op == WS_PING) {
            ws_put(&c->out, WS_PONG, p, n, NULL, 0);
        } else if (op == WS_CLOSE) {
            ws_put(&c->out, WS_CLOSE, p, n >= 2 ? 2 : 0, NULL, 0);
            c->closing = 1;
            c->deadline = time(NULL) + 5;
        } else if (op != WS_PONG) {
            note("%s: unexpected websocket message", c->addr);
            c->dead = 1;
        }
        buf_consume(&c->in, fs);
    }
    if (k < 0) {
        note("%s: bad websocket frame", c->addr);
        c->dead = 1;
    }
}

static void tcp_read(struct client *c)
{
    uint8_t type;
    const uint8_t *p;
    size_t n, fs;
    int k = 0;
    while (!c->dead && (k = frame_peek(&c->in, &type, &p, &n, &fs)) == 1) {
        handle_frame(c, type, p, n);
        buf_consume(&c->in, fs);
    }
    if (k < 0) {
        note("%s: malformed frame", c->addr);
        c->dead = 1;
    }
}

static void client_read(struct client *c)
{
    buf_reserve(&c->in, 16384);
    ssize_t r = recv(c->fd, c->in.data + c->in.len, c->in.cap - c->in.len, 0);
    if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR)) {
        c->dead = 1;
        return;
    }
    if (r < 0)
        return;
    c->in.len += (size_t)r;
    if (c->st == ST_HTTP)
        http_read(c);
    if (c->dead || c->closing || c->st == ST_HTTP)
        return;
    if (c->ws)
        ws_read(c);
    else
        tcp_read(c);
}

static void client_write(struct client *c)
{
    ssize_t r = send(c->fd, c->out.data, c->out.len, MSG_NOSIGNAL);
    if (r < 0 && errno != EAGAIN && errno != EINTR)
        c->dead = 1;
    else if (r > 0)
        buf_consume(&c->out, (size_t)r);
}

static void client_close(int i)
{
    struct client *c = clients[i];
    clients[i] = NULL;
    /* Close code 4000 tells the web client it was refused, 1000 is a normal close. */
    if (c->ws && !c->closing)
        ws_put(&c->out, WS_CLOSE, c->refused ? "\x0f\xa0" : "\x03\xe8", 2, NULL, 0);
    if (c->out.len) /* best effort, so a final error message gets through */
        send(c->fd, c->out.data, c->out.len, MSG_NOSIGNAL | MSG_DONTWAIT);
    close(c->fd);
    if (c->counted) {
        struct limit *l = limit_get(c->ip);
        if (l->conns > 0)
            l->conns--;
    }
    if (c->st == ST_READY) {
        note("%s: %s left", c->addr, c->name);
        struct buf b = { 0 };
        name_put(&b, c->name);
        for (int j = 0; j < MAX_CLIENTS; j++)
            if (clients[j] && clients[j]->st == ST_READY && same_room(clients[j], c))
                send_to(clients[j], T_LEAVE, b.data, b.len);
        buf_free(&b);
    }
    buf_free(&c->in);
    buf_free(&c->out);
    free(c);
}

/* Refuse a connection before it gets a slot, with a one-line reason. */
static void refuse(int fd, int web)
{
    static const char http[] = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n"
                               "Connection: close\r\n\r\n";
    static const char msg[] = "too many connections from your address; try again later";
    if (web) {
        send(fd, http, sizeof http - 1, MSG_NOSIGNAL | MSG_DONTWAIT);
    } else {
        struct buf b = { 0 };
        frame_put(&b, T_ERROR, msg, sizeof msg - 1);
        send(fd, b.data, b.len, MSG_NOSIGNAL | MSG_DONTWAIT);
        buf_free(&b);
    }
    close(fd);
}

static void accept_client(int lfd, int web)
{
    for (int round = 0; round < 64; round++) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        int fd = accept4(lfd, (struct sockaddr *)&ss, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0)
            return;
        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS && slot < 0; i++)
            if (!clients[i])
                slot = i;
        if (slot < 0) {
            refuse(fd, web);
            continue;
        }
        struct client *c = calloc(1, sizeof *c);
        if (!c)
            die("out of memory");
        struct in6_addr a;
        sa_to_in6(&ss, &a);
        ip_use(c, &a);
        /* Behind a local reverse proxy, limits apply once the request says who it's for. */
        c->proxied = web && trust_proxy && ip_loopback(&a);
        if (!c->proxied) {
            struct limit *l = limit_get(c->ip);
            if (l->conns >= IP_CONNS || l->conn < 1) {
                free(c);
                refuse(fd, web);
                continue;
            }
            l->conn -= 1;
            l->conns++;
            c->counted = 1;
        }
        c->fd = fd;
        c->st = web ? ST_HTTP : ST_HELLO;
        c->deadline = time(NULL) + (web ? HTTP_TIMEOUT : AUTH_TIMEOUT);
        clients[slot] = c;
    }
}

/* Listen on all interfaces, dual-stack IPv6 when available. */
static int listen_on(const char *port)
{
    int families[] = { AF_INET6, AF_INET };
    for (size_t f = 0; f < 2; f++) {
        struct addrinfo hints = { .ai_family = families[f], .ai_socktype = SOCK_STREAM,
                                  .ai_flags = AI_PASSIVE },
                        *res;
        int err = getaddrinfo(NULL, port, &hints, &res);
        if (err)
            die("bad port %s: %s", port, gai_strerror(err));
        int fd = socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd >= 0) {
            int one = 1, zero = 0;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
            if (res->ai_family == AF_INET6)
                setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
            if (bind(fd, res->ai_addr, res->ai_addrlen) == 0 && listen(fd, 128) == 0) {
                freeaddrinfo(res);
                return fd;
            }
            err = errno;
            close(fd);
            if (families[f] == AF_INET)
                die("cannot listen on port %s: %s", port, strerror(err));
        }
        freeaddrinfo(res);
    }
    die("cannot create a socket: %s", strerror(errno));
}

/* The web client's files: ./web when run from the source tree, else where
 * `make install` put them, next to this binary's bin directory. */
static const char *find_web_dir(void)
{
    static char dir[4200];
    char exe[4096];
    if (access("web/index.html", R_OK) == 0)
        return "web";
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n <= 0)
        return "web";
    exe[n] = '\0';
    char *slash = strrchr(exe, '/');
    if (slash)
        *slash = '\0';
    snprintf(dir, sizeof dir, "%s/../share/hush/web", exe);
    return dir;
}

/* ---- admin commands ----------------------------------------------------------- */

static void cmd_newkey(const char *label)
{
    if (!label || !name_valid(label, strlen(label)))
        die("give the chat a name: 1-24 of A-Z a-z 0-9 _ . -   e.g. hushd newkey friends");
    keys_load();
    if (room_by_label(label))
        die("there is already a key called %s (hushd revoke %s to replace it)", label, label);
    char key[KEY_CHARS + KEY_CHARS / 4], *o = key;
    for (int i = 0; i < KEY_CHARS; i++) {
        if (i && i % 4 == 0)
            *o++ = '-';
        *o++ = key_alphabet[randombytes_uniform(sizeof key_alphabet - 1)];
    }
    *o = '\0';
    struct room r = { 0 };
    key_hash((const uint8_t *)key, strlen(key), r.hash);
    strcpy(r.label, label);
    room_add(&r);
    file_replace(keys_path, keys_write);
    printf("New key for the chat \"%s\":\n\n    %s\n\n"
           "Give it to the people you want in this chat. Anyone who has it can join.\n"
           "It is not stored anywhere (only a hash of it is, in %s), so this is\n"
           "the only time it's shown. A running hushd picks it up by itself.\n",
           label, key, keys_path);
    sodium_memzero(key, sizeof key);
}

static void cmd_keys(void)
{
    keys_load();
    if (!nrooms)
        printf("no keys yet; create one with: hushd newkey NAME\n");
    for (size_t i = 0; i < nrooms; i++)
        printf("%s\n", rooms[i].label);
}

static void cmd_revoke(const char *label)
{
    keys_load();
    struct room *r = label ? room_by_label(label) : NULL;
    if (!r)
        die("no key called %s (see hushd keys)", label ? label : "?");
    *r = rooms[--nrooms];
    file_replace(keys_path, keys_write);
    printf("revoked %s; a running hushd disconnects everyone in that chat\n", label);
}

static void cmd_forget(const char *name)
{
    users_load();
    struct user *u = name ? user_find(name) : NULL;
    if (!u)
        die("no user called %s", name ? name : "?");
    *u = users[--nusers];
    file_replace(users_path, users_write);
    printf("forgot %s; the next person to log in with that name gets it\n", name);
}

static void usage(void)
{
    fprintf(stderr,
            "usage: hushd [options]              run the server\n"
            "       hushd [options] newkey NAME  create a key for a new chat called NAME\n"
            "       hushd [options] keys         list chats\n"
            "       hushd [options] revoke NAME  delete a chat's key, disconnecting everyone in it\n"
            "       hushd [options] forget USER  free up a name (e.g. a friend lost their key)\n"
            "options:\n"
            "  -p port       port for terminal clients (default " HUSH_DEFAULT_PORT ")\n"
            "  -w port       port for the web client, 0 for none (default " HUSH_DEFAULT_WEB ")\n"
            "  -d dir        web client files (default ./web, else ../share/hush/web from hushd)\n"
            "  -k keys-file  chat key hashes (default %s)\n"
            "  -u users-file name->key registrations (default %s)\n"
            "  -x            trust X-Forwarded-For from a reverse proxy on this machine\n",
            keys_path, users_path);
    exit(2);
}

int main(int argc, char **argv)
{
    const char *port = HUSH_DEFAULT_PORT, *web_port = HUSH_DEFAULT_WEB, *web_dir = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "p:w:d:k:u:xh")) != -1) {
        if (opt == 'p')
            port = optarg;
        else if (opt == 'w')
            web_port = optarg;
        else if (opt == 'd')
            web_dir = optarg;
        else if (opt == 'k')
            keys_path = optarg;
        else if (opt == 'u')
            users_path = optarg;
        else if (opt == 'x')
            trust_proxy = 1;
        else
            usage();
    }
    if (sodium_init() < 0)
        die("libsodium failed to initialise");
    umask(077);

    if (optind < argc) {
        const char *cmd = argv[optind], *arg = optind + 1 < argc ? argv[optind + 1] : NULL;
        if (argc - optind > 2)
            usage();
        if (!strcmp(cmd, "newkey"))
            cmd_newkey(arg);
        else if (!strcmp(cmd, "keys") && !arg)
            cmd_keys();
        else if (!strcmp(cmd, "revoke"))
            cmd_revoke(arg);
        else if (!strcmp(cmd, "forget"))
            cmd_forget(arg);
        else
            usage();
        return 0;
    }

    signal(SIGPIPE, SIG_IGN);
    users_load();
    keys_load();
    file_changed(users_path, &users_st);
    file_changed(keys_path, &keys_st);

    int web = strcmp(web_port, "0") != 0;
    if (web) {
        if (!web_dir)
            web_dir = find_web_dir();
        if (web_load(web_dir) < 0)
            die("cannot load the web client from %s: %s (use -d DIR, or -w 0 to turn it off)",
                web_dir, strerror(errno));
    }
    int lfd = listen_on(port), wfd = web ? listen_on(web_port) : -1;
    note("hushd: terminal clients on port %s", port);
    if (web)
        note("hushd: web client on port %s (files from %s)%s", web_port, web_dir,
             trust_proxy ? ", trusting X-Forwarded-For from localhost" : "");
    note("hushd: %zu chats in %s, %zu registered users in %s", nrooms, keys_path, nusers,
         users_path);
    if (!nrooms)
        note("hushd: no chats yet; create one with: hushd newkey NAME");

    static struct pollfd pfds[MAX_CLIENTS + 2];
    static int slot_of[MAX_CLIENTS + 2];
    for (;;) {
        int n = 0;
        pfds[n++] = (struct pollfd){ .fd = lfd, .events = POLLIN };
        pfds[n++] = (struct pollfd){ .fd = wfd, .events = POLLIN }; /* fd -1 is ignored */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            struct client *c = clients[i];
            if (!c)
                continue;
            short ev = c->out.len ? POLLOUT : 0;
            if (!c->closing)
                ev |= POLLIN;
            pfds[n] = (struct pollfd){ .fd = c->fd, .events = ev };
            slot_of[n++] = i;
        }
        if (poll(pfds, n, 1000) < 0) {
            if (errno == EINTR)
                continue;
            die("poll: %s", strerror(errno));
        }
        if (pfds[0].revents & POLLIN)
            accept_client(lfd, 0);
        if (pfds[1].revents & POLLIN)
            accept_client(wfd, 1);
        for (int k = 2; k < n; k++) {
            struct client *c = clients[slot_of[k]];
            if (!c || c->dead)
                continue;
            if (!c->closing && (pfds[k].revents & (POLLIN | POLLHUP | POLLERR)))
                client_read(c);
            else if (pfds[k].revents & (POLLHUP | POLLERR))
                c->dead = 1;
            if (!c->dead && (pfds[k].revents & POLLOUT))
                client_write(c);
        }

        /* Pick up `hushd newkey/revoke/forget` run while we're up. */
        if (file_changed(users_path, &users_st))
            users_load();
        if (file_changed(keys_path, &keys_st)) {
            keys_load();
            note("hushd: reloaded %s (%zu chats)", keys_path, nrooms);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                struct client *c = clients[i];
                if (c && (c->st == ST_AUTH || c->st == ST_READY) && !room_find(c->room))
                    send_error(c, "this chat's key was revoked", 1);
            }
        }

        time_t now = time(NULL);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            struct client *c = clients[i];
            if (!c)
                continue;
            if ((c->deadline && now > c->deadline) || (c->closing && !c->out.len))
                c->dead = 1;
            if (c->dead)
                client_close(i);
        }
    }
}
