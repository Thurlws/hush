/* hushd: the hush server. It lets people into a chat only with a key the
 * admin created, authenticates them by their signing key, stores their
 * encrypted messages and images, and passes them on. It never holds a key
 * that can decrypt anything. It also serves the web client, which speaks
 * the same protocol over a WebSocket. */
#include "msg.h"
#include "proto.h"
#include "web.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS  512
#define MAX_OUTBUF   (4u << 20)
#define AUTH_TIMEOUT 15 /* seconds a connection may spend in the handshake */
#define HTTP_TIMEOUT 10 /* ... sending its HTTP request */
#define SEND_TIMEOUT 60 /* ... downloading a response */
#define MIN_FREE_DISK (1ull << 30) /* refuse uploads below this */
#define MAX_FETCHES  16 /* queued image downloads per connection */
#define MAX_WAITING  50 /* people on one chat's waitlist */

/* Per-address limits. IPv6 addresses count per /64, since one machine
 * usually has a whole /64 to pick from. */
#define IP_CONNS    16                 /* open connections */
#define CONN_BURST  30.0               /* new connections and HTTP requests ... */
#define CONN_RATE   0.5                /* ... refilled per second */
#define AUTH_BURST  5.0                /* wrong chat keys ... */
#define AUTH_RATE   (1.0 / 60)         /* ... refilled per second */
#define UP_BURST    (100.0 * (1 << 20)) /* uploaded bytes ... */
#define UP_RATE     (1.0 * (1 << 20))  /* ... refilled per second */
/* Per connection: messages, history requests and downloads. */
#define REQ_BURST 60.0
#define REQ_RATE  5.0

enum cstate { ST_HTTP, ST_HELLO, ST_AUTH, ST_WAITING, ST_READY, ST_ADMIN };
/* A name's standing in a chat (members.state). */
enum { MEMBER_NONE = -1, MEMBER_WAITING = 0, MEMBER_IN = 1, MEMBER_DENIED = 2 };

struct client {
    int fd;
    enum cstate st;
    int ws;       /* speaks WebSocket (web client) */
    int proxied;  /* came through a trusted local reverse proxy */
    int counted;  /* holds one of its address's connection slots */
    int dead, closing;
    int refused;     /* dropped with an error, web clients shouldn't reconnect */
    int admin;       /* its identity key is on the admin list */
    int no_chat;     /* logged in with a zero token, to create chats */
    time_t deadline; /* drop the connection after this, 0 for never */
    uint8_t ip[16];  /* rate-limit key */
    char addr[INET6_ADDRSTRLEN];
    char name[HUSH_NAME_MAX + 1];
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t challenge[HUSH_CHALLENGE_LEN];
    uint8_t room[32];
    double req_tokens, req_t;
    struct buf in, out;
    /* image upload in progress */
    int up_fd;
    size_t up_len;
    char up_path[64];
    /* image downloads: the one being sent, then the queue */
    int dl_fd;
    uint8_t dl_id[HUSH_BLOB_ID];
    off_t dl_off, dl_size;
    uint8_t fetch_q[MAX_FETCHES][HUSH_BLOB_ID];
    int fetch_n;
};

/* Names are pinned to the first key that claims them, so nobody can take
 * over a friend's name on this server. */
struct user {
    char name[HUSH_NAME_MAX + 1];
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
};

/* A chat, known only by the hash of its login token. */
struct room {
    uint8_t hash[32];
    char label[HUSH_NAME_MAX + 1];
    int old; /* old-format key, can only be revoked */
};

struct limit {
    uint8_t ip[16];
    int used, conns;
    double conn, auth, up, t;
};

static struct client *clients[MAX_CLIENTS];
static struct user *users;
static size_t nusers;
static struct room *rooms;
static size_t nrooms;
static const char *users_path = "hushd-users.txt", *keys_path = "hushd-keys.txt";
static const char *db_path = "hushd.db", *blob_dir = "blobs", *admins_path = "hushd-admins.txt";
static struct stat users_st, keys_st, admins_st;
/* Admins are identity keys, listed by fingerprint (BLAKE2b-128 of the key). */
static uint8_t (*admins)[16];
static size_t nadmins;
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
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static double refill(double tokens, double burst, double rate, double dt)
{
    tokens += dt * rate;
    return tokens > burst ? burst : tokens;
}

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

/* Limits for an address, refilled. With no free slot, the one with the fewest
 * open connections (then the longest idle) gets reused. */
static struct limit *limit_get(const uint8_t ip[16])
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 16; i++)
        h = (h ^ ip[i]) * 16777619u;
    double now = now_mono();
    struct limit *l = NULL, *spare = NULL;
    for (int i = 0; i < LIMIT_PROBE && !l; i++) {
        struct limit *e = &limits[(h + (uint32_t)i) % LIMIT_SLOTS];
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
        l->up = UP_BURST;
    } else {
        l->conn = refill(l->conn, CONN_BURST, CONN_RATE, now - l->t);
        l->auth = refill(l->auth, AUTH_BURST, AUTH_RATE, now - l->t);
        l->up = refill(l->up, UP_BURST, UP_RATE, now - l->t);
    }
    l->t = now;
    return l;
}

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
        if (!rooms[i].old && !sodium_memcmp(rooms[i].hash, hash, sizeof rooms[i].hash))
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

/* Lines are "3 HASH LABEL". Two-field lines are keys from before chat
 * keys changed: kept so they can be listed and revoked, but unusable. */
static void keys_load(void)
{
    nrooms = 0;
    FILE *f = fopen(keys_path, "r");
    if (!f) {
        if (errno != ENOENT)
            note("cannot read %s: %s", keys_path, strerror(errno));
        return;
    }
    char line[256], a[128], b[128], c[128];
    while (fgets(line, sizeof line, f)) {
        struct room r = { 0 };
        size_t bl;
        const char *hex, *label;
        int n = sscanf(line, "%127s %127s %127s", a, b, c);
        if (n == 3 && !strcmp(a, "3"))
            hex = b, label = c;
        else if (n == 2)
            hex = a, label = b, r.old = 1;
        else
            continue;
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

/* Replace path with the output of write_fn, atomically. Returns -1 on failure. */
static int file_write(const char *path, void (*write_fn)(FILE *))
{
    char tmp[4200];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f)
        return -1;
    write_fn(f);
    int ok = fflush(f) == 0 && fsync(fileno(f)) == 0;
    if (fclose(f) != 0 || !ok || rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static void file_replace(const char *path, void (*write_fn)(FILE *))
{
    if (file_write(path, write_fn) != 0)
        die("cannot write %s: %s", path, strerror(errno));
}

static void keys_write(FILE *f)
{
    for (size_t i = 0; i < nrooms; i++) {
        char hex[sizeof rooms[i].hash * 2 + 1];
        sodium_bin2hex(hex, sizeof hex, rooms[i].hash, sizeof rooms[i].hash);
        if (rooms[i].old)
            fprintf(f, "%s %s\n", hex, rooms[i].label);
        else
            fprintf(f, "3 %s %s\n", hex, rooms[i].label);
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

/* Parse a fingerprint as shown to users ("6937 b1d5 ...", any case, spaces
 * optional) into 16 bytes. Returns -1 if it isn't one. */
static int fingerprint_parse(const char *s, uint8_t out[16])
{
    char hex[33];
    size_t k = 0;
    for (; *s; s++) {
        if (*s == ' ')
            continue;
        if (k == 32)
            return -1;
        hex[k++] = *s;
    }
    hex[k] = '\0';
    size_t bl;
    return k == 32 && sodium_hex2bin(out, 16, hex, 32, NULL, &bl, NULL) == 0 && bl == 16 ? 0 : -1;
}

static void admins_load(void)
{
    nadmins = 0;
    FILE *f = fopen(admins_path, "r");
    if (!f)
        return;
    char line[256];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "#\r\n")] = '\0';
        uint8_t fp[16];
        if (fingerprint_parse(line, fp) != 0)
            continue;
        void *p = realloc(admins, (nadmins + 1) * sizeof *admins);
        if (!p)
            die("out of memory");
        admins = p;
        memcpy(admins[nadmins++], fp, 16);
    }
    fclose(f);
}

static void admins_write(FILE *f)
{
    for (size_t i = 0; i < nadmins; i++) {
        char hex[33];
        sodium_bin2hex(hex, sizeof hex, admins[i], 16);
        fprintf(f, "%s\n", hex);
    }
}

static int is_admin(const uint8_t pk[crypto_sign_PUBLICKEYBYTES])
{
    uint8_t fp[16];
    crypto_generichash(fp, sizeof fp, pk, crypto_sign_PUBLICKEYBYTES, NULL, 0);
    for (size_t i = 0; i < nadmins; i++)
        if (!sodium_memcmp(admins[i], fp, sizeof fp))
            return 1;
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

/* Messages and members are in SQLite, images are files in blob_dir.
 * All queries are prepared statements with bound parameters. */

static sqlite3 *db;
enum {
    Q_INSERT_MSG, Q_OLDER, Q_NEWER, Q_MINE, Q_ADD_MEMBER, Q_MEMBERS, Q_IS_MEMBER,
    Q_MEMBER_STATE, Q_SET_STATE, Q_WAITING, Q_COUNT_WAITING,
    Q_ADD_BLOB, Q_BLOB_ROOM, NQUERIES
};
static const char *const query_sql[NQUERIES] = {
    [Q_INSERT_MSG] = "INSERT INTO messages (room, sender, recipient, time, body) VALUES (?1, ?2, ?3, ?4, ?5)",
    [Q_OLDER] = "SELECT id, time, sender, recipient, body FROM messages WHERE room = ?1 AND id < ?2 "
                "AND (recipient IS NULL OR recipient = ?3 OR sender = ?3) ORDER BY id DESC LIMIT ?4",
    [Q_NEWER] = "SELECT id, time, sender, recipient, body FROM messages WHERE room = ?1 AND id > ?2 "
                "AND (recipient IS NULL OR recipient = ?3 OR sender = ?3) ORDER BY id ASC LIMIT ?4",
    [Q_MINE] = "SELECT id, time, sender, recipient, body FROM messages WHERE room = ?1 AND id > ?2 "
               "AND (sender = ?3 OR recipient = ?3) ORDER BY id ASC LIMIT ?4",
    [Q_ADD_MEMBER] = "INSERT OR IGNORE INTO members (room, name, state) VALUES (?1, ?2, ?3)",
    [Q_MEMBERS] = "SELECT name FROM members WHERE room = ?1 AND state = 1 ORDER BY name",
    [Q_IS_MEMBER] = "SELECT 1 FROM members WHERE room = ?1 AND name = ?2 AND state = 1",
    [Q_MEMBER_STATE] = "SELECT state FROM members WHERE room = ?1 AND name = ?2",
    [Q_SET_STATE] = "UPDATE members SET state = ?3 WHERE room = ?1 AND name = ?2",
    [Q_WAITING] = "SELECT name FROM members WHERE room = ?1 AND state = 0 ORDER BY name",
    [Q_COUNT_WAITING] = "SELECT count(*) FROM members WHERE room = ?1 AND state = 0",
    [Q_ADD_BLOB] = "INSERT INTO blobs (id, room, size, time) VALUES (?1, ?2, ?3, ?4)",
    [Q_BLOB_ROOM] = "SELECT room FROM blobs WHERE id = ?1",
};
static sqlite3_stmt *queries[NQUERIES];

static void db_exec(const char *sql)
{
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK)
        die("database %s: %s", db_path, err ? err : "error");
}

static void db_open(void)
{
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK)
        die("cannot open %s: %s", db_path, sqlite3_errmsg(db));
    sqlite3_busy_timeout(db, 5000);
    db_exec("PRAGMA journal_mode = WAL;"
            "PRAGMA foreign_keys = ON;"
            "CREATE TABLE IF NOT EXISTS messages ("
            "  id INTEGER PRIMARY KEY, room BLOB NOT NULL, sender TEXT NOT NULL,"
            "  recipient TEXT, time INTEGER NOT NULL, body BLOB NOT NULL);"
            "CREATE INDEX IF NOT EXISTS messages_room ON messages (room, id);"
            "CREATE TABLE IF NOT EXISTS members ("
            "  room BLOB NOT NULL, name TEXT NOT NULL, state INTEGER NOT NULL DEFAULT 1,"
            "  PRIMARY KEY (room, name));"
            "CREATE TABLE IF NOT EXISTS blobs ("
            "  id BLOB PRIMARY KEY, room BLOB NOT NULL, size INTEGER NOT NULL, time INTEGER NOT NULL);"
            "CREATE INDEX IF NOT EXISTS blobs_room ON blobs (room);");
    /* Members from before the waitlist existed stay in. */
    sqlite3_stmt *probe;
    if (sqlite3_prepare_v2(db, "SELECT state FROM members LIMIT 0", -1, &probe, NULL) != SQLITE_OK)
        db_exec("ALTER TABLE members ADD COLUMN state INTEGER NOT NULL DEFAULT 1");
    else
        sqlite3_finalize(probe);
    for (int i = 0; i < NQUERIES; i++)
        if (sqlite3_prepare_v3(db, query_sql[i], -1, SQLITE_PREPARE_PERSISTENT, &queries[i], NULL) !=
            SQLITE_OK)
            die("database %s: %s", db_path, sqlite3_errmsg(db));
    if (mkdir(blob_dir, 0700) < 0 && errno != EEXIST)
        die("cannot create %s: %s", blob_dir, strerror(errno));
}

static sqlite3_stmt *q(int which)
{
    sqlite3_stmt *s = queries[which];
    sqlite3_reset(s);
    sqlite3_clear_bindings(s);
    return s;
}

static int is_member(const uint8_t *room, const char *name)
{
    sqlite3_stmt *s = q(Q_IS_MEMBER);
    sqlite3_bind_blob(s, 1, room, 32, SQLITE_STATIC);
    sqlite3_bind_text(s, 2, name, -1, SQLITE_STATIC);
    int yes = sqlite3_step(s) == SQLITE_ROW;
    sqlite3_reset(s); /* an unfinished statement would pin an old snapshot of the database */
    return yes;
}

static int member_state(const uint8_t *room, const char *name)
{
    sqlite3_stmt *s = q(Q_MEMBER_STATE);
    sqlite3_bind_blob(s, 1, room, 32, SQLITE_STATIC);
    sqlite3_bind_text(s, 2, name, -1, SQLITE_STATIC);
    int state = sqlite3_step(s) == SQLITE_ROW ? sqlite3_column_int(s, 0) : MEMBER_NONE;
    sqlite3_reset(s);
    return state;
}

static void set_member_state(const uint8_t *room, const char *name, int state)
{
    sqlite3_stmt *s = q(member_state(room, name) == MEMBER_NONE ? Q_ADD_MEMBER : Q_SET_STATE);
    sqlite3_bind_blob(s, 1, room, 32, SQLITE_STATIC);
    sqlite3_bind_text(s, 2, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(s, 3, state);
    if (sqlite3_step(s) != SQLITE_DONE)
        note("updating chat members failed: %s", sqlite3_errmsg(db));
    sqlite3_reset(s);
}

static void blob_path(const uint8_t id[HUSH_BLOB_ID], char *out, size_t n)
{
    char hex[HUSH_BLOB_ID * 2 + 1];
    sodium_bin2hex(hex, sizeof hex, id, HUSH_BLOB_ID);
    snprintf(out, n, "%s/%s", blob_dir, hex);
}

static int disk_low(void)
{
    struct statvfs sv;
    return statvfs(blob_dir, &sv) == 0 && (unsigned long long)sv.f_bavail * sv.f_frsize < MIN_FREE_DISK;
}

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

static void send_peer(struct client *to, const char *name, const uint8_t *pk, uint8_t flags)
{
    struct buf b = { 0 };
    name_put(&b, name);
    buf_put(&b, pk, crypto_sign_PUBLICKEYBYTES);
    buf_put(&b, &flags, 1);
    send_to(to, T_PEER, b.data, b.len);
    buf_free(&b);
}

/* Messages, history requests and downloads share one allowance per connection. */
static int take_request(struct client *c)
{
    double now = now_mono();
    c->req_tokens = refill(c->req_tokens, REQ_BURST, REQ_RATE, now - c->req_t);
    c->req_t = now;
    if (c->req_tokens < 1) {
        note("%s: %s is sending too fast, dropping", c->addr, c->name);
        send_error(c, "you are sending too fast", 1);
        return 0;
    }
    c->req_tokens -= 1;
    return 1;
}

static void on_hello(struct client *c, const uint8_t *p, size_t n)
{
    int k = name_get(p, n, c->name);
    if (k < 0 || n - (size_t)k != crypto_sign_PUBLICKEYBYTES + 32) {
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
    c->no_chat = sodium_is_zero(p + k + crypto_sign_PUBLICKEYBYTES, 32);
    if (!c->no_chat)
        chat_verifier(p + k + crypto_sign_PUBLICKEYBYTES, c->room);
    if (!c->no_chat && !room_find(c->room)) {
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

/* Tell the admins in room that name is waiting (1) or was decided (0). */
static void notify_admins(const uint8_t *room, uint8_t waiting, const char *name, const uint8_t *pk)
{
    struct buf b = { 0 };
    buf_put(&b, &waiting, 1);
    name_put(&b, name);
    buf_put(&b, pk, crypto_sign_PUBLICKEYBYTES);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        struct client *o = clients[i];
        if (o && !o->dead && o->st == ST_READY && o->admin && !memcmp(o->room, room, 32))
            send_to(o, T_PENDING, b.data, b.len);
    }
    buf_free(&b);
}

/* Let c into its chat: welcome, members, and (for admins) the waitlist. */
static void admit(struct client *c, int is_new)
{
    const struct room *r = room_find(c->room);
    if (!r) {
        send_error(c, "this chat's key was revoked", 1);
        return;
    }
    c->st = ST_READY;
    c->deadline = 0;
    c->req_tokens = REQ_BURST;
    c->req_t = now_mono();
    note("%s: %s joined %s%s", c->addr, c->name, r->label, c->admin ? " (admin)" : "");

    struct buf b = { 0 };
    uint8_t flags = c->admin ? WELCOME_ADMIN : 0;
    name_put(&b, r->label);
    buf_put(&b, &flags, 1);
    send_to(c, T_WELCOME, b.data, b.len);
    buf_free(&b);

    /* Everyone in the chat, online or not, so DMs can be encrypted for them. */
    sqlite3_stmt *s = q(Q_MEMBERS);
    sqlite3_bind_blob(s, 1, c->room, 32, SQLITE_STATIC);
    while (sqlite3_step(s) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(s, 0);
        const struct user *u = name ? user_find(name) : NULL;
        struct client *o = u ? client_find(name) : NULL;
        if (!u || o == c)
            continue;
        send_peer(c, u->name, u->pk, o && same_room(o, c) ? PEER_ONLINE : 0);
    }
    sqlite3_reset(s);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        struct client *o = clients[i];
        if (o && o != c && !o->dead && o->st == ST_READY && same_room(o, c))
            send_peer(o, c->name, c->pk, PEER_ONLINE | (is_new ? PEER_NEW : 0));
    }
    if (!c->admin)
        return;
    s = q(Q_WAITING);
    sqlite3_bind_blob(s, 1, c->room, 32, SQLITE_STATIC);
    b = (struct buf){ 0 };
    while (sqlite3_step(s) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(s, 0);
        const struct user *u = name ? user_find(name) : NULL;
        if (!u)
            continue;
        uint8_t waiting = 1;
        b.len = 0;
        buf_put(&b, &waiting, 1);
        name_put(&b, u->name);
        buf_put(&b, u->pk, sizeof u->pk);
        send_to(c, T_PENDING, b.data, b.len);
    }
    sqlite3_reset(s);
    buf_free(&b);
}

static void refuse_denied(struct client *c)
{
    note("%s: %s was not let into the chat", c->addr, c->name);
    send_error(c, "the admin didn't let you into this chat", 1);
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
    if (c->no_chat) { /* admins creating a chat from the home page */
        c->admin = is_admin(c->pk);
        if (!c->admin) {
            limit_get(c->ip)->auth -= 1;
            note("%s: %s tried to create a chat without being an admin", c->addr, c->name);
            send_error(c, "only an admin can create chats", 1);
            return;
        }
        c->st = ST_ADMIN;
        c->deadline = time(NULL) + 60;
        c->req_tokens = REQ_BURST;
        c->req_t = now_mono();
        send_to(c, T_ADMIN, NULL, 0);
        return;
    }
    const struct room *r = room_find(c->room);
    if (!r) {
        send_error(c, "this chat's key was revoked", 1);
        return;
    }
    for (int i = 0; i < MAX_CLIENTS; i++) {
        struct client *o = clients[i];
        if (o && o != c && !o->dead && (o->st == ST_READY || o->st == ST_WAITING) &&
            !strcmp(o->name, c->name)) {
            send_error(c, "that name is already connected", 1);
            return;
        }
    }
    if (!user_find(c->name)) {
        user_pin(c->name, c->pk);
        note("%s: registered new user %s", c->addr, c->name);
    }
    c->admin = is_admin(c->pk);
    int state = member_state(c->room, c->name);
    if (state == MEMBER_IN) {
        admit(c, 0);
        return;
    }
    if (c->admin) {
        set_member_state(c->room, c->name, MEMBER_IN);
        admit(c, 1);
        return;
    }
    if (state == MEMBER_DENIED) {
        refuse_denied(c);
        return;
    }
    if (state == MEMBER_NONE) {
        sqlite3_stmt *s = q(Q_COUNT_WAITING);
        sqlite3_bind_blob(s, 1, c->room, 32, SQLITE_STATIC);
        int waiting = sqlite3_step(s) == SQLITE_ROW ? sqlite3_column_int(s, 0) : 0;
        sqlite3_reset(s);
        if (waiting >= MAX_WAITING) {
            send_error(c, "the waitlist for this chat is full; try again later", 1);
            return;
        }
        set_member_state(c->room, c->name, MEMBER_WAITING);
        notify_admins(c->room, 1, c->name, c->pk);
    }
    c->st = ST_WAITING;
    c->deadline = 0;
    note("%s: %s is waiting to join %s", c->addr, c->name, r->label);
    struct buf b = { 0 };
    name_put(&b, r->label);
    send_to(c, T_WAITING, b.data, b.len);
    buf_free(&b);
}

/* A waiting client may have been approved or denied (by an admin in the chat,
 * with `hushd approve`, or by becoming an admin). Act on it. */
static void recheck_waiting(struct client *c)
{
    c->admin = is_admin(c->pk);
    int state = member_state(c->room, c->name);
    if (c->admin && state != MEMBER_IN) {
        set_member_state(c->room, c->name, MEMBER_IN);
        notify_admins(c->room, 0, c->name, c->pk);
        state = MEMBER_IN;
    }
    if (state == MEMBER_IN)
        admit(c, 1);
    else if (state == MEMBER_DENIED || state == MEMBER_NONE)
        refuse_denied(c);
}

static void on_decide(struct client *c, const uint8_t *p, size_t n)
{
    char name[HUSH_NAME_MAX + 1];
    if (n < 2 || p[0] > 1 || name_get(p + 1, n - 1, name) != (int)n - 1) {
        send_error(c, "malformed decision", 1);
        return;
    }
    if (!c->admin) {
        send_error(c, "only an admin can do that", 0);
        return;
    }
    const struct user *u = user_find(name);
    if (!u || member_state(c->room, name) != MEMBER_WAITING) {
        char msg[64 + HUSH_NAME_MAX];
        snprintf(msg, sizeof msg, "%s isn't waiting to join", name);
        send_error(c, msg, 0);
        return;
    }
    set_member_state(c->room, name, p[0] ? MEMBER_IN : MEMBER_DENIED);
    note("%s: %s %s %s", c->addr, c->name, p[0] ? "approved" : "denied", name);
    notify_admins(c->room, 0, name, u->pk);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        struct client *o = clients[i];
        if (o && !o->dead && o->st == ST_WAITING && same_room(o, c) && !strcmp(o->name, name)) {
            recheck_waiting(o);
            return;
        }
    }
    if (p[0]) /* not connected right now: tell the chat they're in */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            struct client *o = clients[i];
            if (o && !o->dead && o->st == ST_READY && same_room(o, c))
                send_peer(o, u->name, u->pk, PEER_NEW);
        }
}

static void msg_frame(struct buf *b, int64_t id, int64_t time, uint8_t live, const char *from,
                      const char *to, const void *body, size_t n)
{
    uint8_t h[17];
    put_u64(h, (uint64_t)id);
    put_u64(h + 8, (uint64_t)time);
    h[16] = live;
    b->len = 0;
    buf_put(b, h, sizeof h);
    name_put(b, from);
    name_put(b, to);
    buf_put(b, body, n);
}

static void on_post(struct client *c, const uint8_t *p, size_t n)
{
    if (!take_request(c))
        return;
    char to[HUSH_NAME_MAX + 1];
    int k = name_get_opt(p, n, to);
    size_t bl = k < 0 ? 0 : n - (size_t)k;
    if (k < 0 || bl < 24 + 16 + 64) {
        send_error(c, "malformed message", 1);
        return;
    }
    if (*to && (!strcmp(to, c->name) || !is_member(c->room, to))) {
        char msg[64 + HUSH_NAME_MAX];
        snprintf(msg, sizeof msg, "there is no %s in this chat", to);
        send_error(c, msg, 0);
        return;
    }
    int64_t time = (int64_t)now_ms();
    sqlite3_stmt *s = q(Q_INSERT_MSG);
    sqlite3_bind_blob(s, 1, c->room, 32, SQLITE_STATIC);
    sqlite3_bind_text(s, 2, c->name, -1, SQLITE_STATIC);
    if (*to)
        sqlite3_bind_text(s, 3, to, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(s, 3);
    sqlite3_bind_int64(s, 4, time);
    sqlite3_bind_blob(s, 5, p + k, (int)bl, SQLITE_STATIC);
    if (sqlite3_step(s) != SQLITE_DONE) {
        note("storing a message failed: %s", sqlite3_errmsg(db));
        send_error(c, "the server could not store your message", 0);
        return;
    }
    int64_t id = sqlite3_last_insert_rowid(db);

    struct buf b = { 0 };
    msg_frame(&b, id, time, 1, c->name, to, p + k, bl);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        struct client *o = clients[i];
        if (!o || o->dead || o->st != ST_READY || !same_room(o, c))
            continue;
        if (!*to || o == c || !strcmp(o->name, to))
            send_to(o, T_MSG, b.data, b.len);
    }
    buf_free(&b);
}

static void on_history(struct client *c, const uint8_t *p, size_t n)
{
    if (n != 11 || p[0] > HIST_MINE) {
        send_error(c, "malformed history request", 1);
        return;
    }
    if (!take_request(c))
        return;
    int dir = p[0];
    uint64_t anchor = get_u64(p + 1);
    int limit = get_u16(p + 9);
    if (limit < 1 || limit > HUSH_HISTORY_MAX)
        limit = HUSH_HISTORY_MAX;
    if (dir == 0 && (anchor == 0 || anchor > INT64_MAX))
        anchor = INT64_MAX;
    if (anchor > INT64_MAX)
        anchor = INT64_MAX;

    sqlite3_stmt *s = q(dir == HIST_OLDER ? Q_OLDER : dir == HIST_NEWER ? Q_NEWER : Q_MINE);
    sqlite3_bind_blob(s, 1, c->room, 32, SQLITE_STATIC);
    sqlite3_bind_int64(s, 2, (int64_t)anchor);
    sqlite3_bind_text(s, 3, c->name, -1, SQLITE_STATIC);
    sqlite3_bind_int(s, 4, limit + 1); /* one extra says whether there's more */

    /* Older pages come newest first, so collect them and send reversed. */
    struct buf frames[HUSH_HISTORY_MAX];
    int rows = 0, more = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {
        if (rows == limit) {
            more = 1;
            break;
        }
        const char *from = (const char *)sqlite3_column_text(s, 2);
        const char *to = (const char *)sqlite3_column_text(s, 3);
        const void *body = sqlite3_column_blob(s, 4);
        int bl = sqlite3_column_bytes(s, 4);
        if (!from || !body)
            continue;
        frames[rows] = (struct buf){ 0 };
        msg_frame(&frames[rows], sqlite3_column_int64(s, 0), sqlite3_column_int64(s, 1), 0, from,
                  to ? to : "", body, (size_t)bl);
        rows++;
    }
    sqlite3_reset(s);
    for (int i = 0; i < rows; i++) {
        struct buf *f = &frames[dir == 0 ? rows - 1 - i : i];
        send_to(c, T_MSG, f->data, f->len);
    }
    for (int i = 0; i < rows; i++)
        buf_free(&frames[i]);
    uint8_t end[2] = { (uint8_t)dir, (uint8_t)more };
    send_to(c, T_HISTORY_END, end, sizeof end);
}

static void upload_abort(struct client *c)
{
    if (c->up_fd < 0)
        return;
    close(c->up_fd);
    unlink(c->up_path);
    c->up_fd = -1;
    c->up_len = 0;
}

static void on_upload(struct client *c, const uint8_t *p, size_t n)
{
    if (n < 1 || p[0] > (UP_FIRST | UP_LAST)) {
        send_error(c, "malformed upload", 1);
        return;
    }
    int first = p[0] & UP_FIRST, last = p[0] & UP_LAST;
    p++, n--;
    if (first)
        upload_abort(c);
    else if (c->up_fd < 0)
        return; /* the rest of an upload we already refused */
    if (c->up_fd < 0) {
        if (disk_low()) {
            note("refusing an upload: less than 1 GB free in %s", blob_dir);
            send_error(c, "the server is low on disk space; image not sent", 0);
            return;
        }
        uint8_t rnd[8];
        char hex[sizeof rnd * 2 + 1];
        randombytes_buf(rnd, sizeof rnd);
        sodium_bin2hex(hex, sizeof hex, rnd, sizeof rnd);
        snprintf(c->up_path, sizeof c->up_path, "%s/.up-%s", blob_dir, hex);
        c->up_fd = open(c->up_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (c->up_fd < 0) {
            note("cannot create %s: %s", c->up_path, strerror(errno));
            send_error(c, "the server could not store your image", 0);
            return;
        }
    }
    struct limit *l = limit_get(c->ip);
    if (c->up_len + n > HUSH_MAX_IMAGE + 24 + 16 || l->up < (double)n) {
        upload_abort(c);
        send_error(c, c->up_len + n > HUSH_MAX_IMAGE + 40 ? "image too big (25 MB at most)"
                                                          : "sending images too fast; try again in a minute",
                   0);
        return;
    }
    l->up -= (double)n;
    if (write(c->up_fd, p, n) != (ssize_t)n) {
        note("writing %s failed: %s", c->up_path, strerror(errno));
        upload_abort(c);
        send_error(c, "the server could not store your image", 0);
        return;
    }
    c->up_len += n;
    if (!last)
        return;

    uint8_t id[HUSH_BLOB_ID];
    char path[128];
    randombytes_buf(id, sizeof id);
    blob_path(id, path, sizeof path);
    int ok = fsync(c->up_fd) == 0;
    close(c->up_fd);
    c->up_fd = -1;
    if (!ok || rename(c->up_path, path) != 0) {
        unlink(c->up_path);
        c->up_len = 0;
        send_error(c, "the server could not store your image", 0);
        return;
    }
    sqlite3_stmt *s = q(Q_ADD_BLOB);
    sqlite3_bind_blob(s, 1, id, sizeof id, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, c->room, 32, SQLITE_STATIC);
    sqlite3_bind_int64(s, 3, (int64_t)c->up_len);
    sqlite3_bind_int64(s, 4, (int64_t)now_ms());
    c->up_len = 0;
    if (sqlite3_step(s) != SQLITE_DONE) {
        unlink(path);
        send_error(c, "the server could not store your image", 0);
        return;
    }
    send_to(c, T_UPLOADED, id, sizeof id);
}

static void blob_reply(struct client *c, const uint8_t *id, uint8_t status, const void *data, size_t n)
{
    struct buf b = { 0 };
    buf_put(&b, id, HUSH_BLOB_ID);
    buf_put(&b, &status, 1);
    buf_put(&b, data, n);
    send_to(c, T_BLOB, b.data, b.len);
    buf_free(&b);
}

/* Queue up more of the current download while the connection keeps up. */
static void pump_downloads(struct client *c)
{
    static uint8_t chunk[HUSH_CHUNK];
    while (!c->dead && !c->closing && c->out.len < 4 * HUSH_CHUNK) {
        if (c->dl_fd < 0) {
            if (!c->fetch_n)
                return;
            memcpy(c->dl_id, c->fetch_q[0], HUSH_BLOB_ID);
            memmove(c->fetch_q, c->fetch_q + 1, (size_t)--c->fetch_n * HUSH_BLOB_ID);
            sqlite3_stmt *s = q(Q_BLOB_ROOM);
            sqlite3_bind_blob(s, 1, c->dl_id, HUSH_BLOB_ID, SQLITE_STATIC);
            int mine = sqlite3_step(s) == SQLITE_ROW && sqlite3_column_bytes(s, 0) == 32 &&
                       !memcmp(sqlite3_column_blob(s, 0), c->room, 32);
            sqlite3_reset(s);
            char path[128];
            struct stat st;
            blob_path(c->dl_id, path, sizeof path);
            if (!mine || (c->dl_fd = open(path, O_RDONLY | O_CLOEXEC)) < 0 ||
                fstat(c->dl_fd, &st) < 0) {
                if (c->dl_fd >= 0)
                    close(c->dl_fd);
                c->dl_fd = -1;
                blob_reply(c, c->dl_id, BLOB_MISSING, NULL, 0);
                continue;
            }
            c->dl_off = 0;
            c->dl_size = st.st_size;
        }
        ssize_t r = pread(c->dl_fd, chunk, sizeof chunk, c->dl_off);
        if (r < 0)
            r = 0;
        c->dl_off += r;
        int last = r == 0 || c->dl_off >= c->dl_size;
        blob_reply(c, c->dl_id, last ? BLOB_LAST : BLOB_PART, chunk, (size_t)r);
        if (last) {
            close(c->dl_fd);
            c->dl_fd = -1;
        }
    }
}

static void on_fetch(struct client *c, const uint8_t *p, size_t n)
{
    if (n != HUSH_BLOB_ID) {
        send_error(c, "malformed download request", 1);
        return;
    }
    if (!take_request(c))
        return;
    if (c->fetch_n == MAX_FETCHES) {
        blob_reply(c, p, BLOB_MISSING, NULL, 0);
        return;
    }
    memcpy(c->fetch_q[c->fetch_n++], p, HUSH_BLOB_ID);
    pump_downloads(c);
}

/* An admin made a chat key in their client and sends its login token. */
static void on_newchat(struct client *c, const uint8_t *p, size_t n)
{
    char label[HUSH_NAME_MAX + 1];
    int k = name_get(p, n, label);
    if (k < 0 || n - (size_t)k != 32) {
        send_error(c, "a chat name is 1-24 of A-Z a-z 0-9 _ . -", 0);
        return;
    }
    if (!c->admin) {
        send_error(c, "only an admin can create chats", 0);
        return;
    }
    if (!take_request(c))
        return;
    struct room r = { 0 };
    chat_verifier(p + k, r.hash);
    char msg[64 + HUSH_NAME_MAX];
    if (room_by_label(label) || room_find(r.hash)) {
        snprintf(msg, sizeof msg, "there is already a chat called %s", label);
        send_error(c, msg, 0);
        return;
    }
    strcpy(r.label, label);
    room_add(&r);
    if (file_write(keys_path, keys_write) != 0) {
        note("cannot write %s: %s", keys_path, strerror(errno));
        nrooms--;
        send_error(c, "the server could not save the new chat", 0);
        return;
    }
    file_changed(keys_path, &keys_st); /* already up to date */
    note("%s: %s created the chat %s", c->addr, c->name, label);
    struct buf b = { 0 };
    name_put(&b, label);
    send_to(c, T_CREATED, b.data, b.len);
    buf_free(&b);
}

static void handle_frame(struct client *c, uint8_t type, const uint8_t *p, size_t n)
{
    if (c->st == ST_HELLO && type == T_HELLO)
        on_hello(c, p, n);
    else if (c->st == ST_AUTH && type == T_AUTH)
        on_auth(c, p, n);
    else if (c->st == ST_READY && type == T_POST)
        on_post(c, p, n);
    else if (c->st == ST_READY && type == T_HISTORY)
        on_history(c, p, n);
    else if (c->st == ST_READY && type == T_UPLOAD)
        on_upload(c, p, n);
    else if (c->st == ST_READY && type == T_FETCH)
        on_fetch(c, p, n);
    else if (c->st == ST_READY && type == T_DECIDE)
        on_decide(c, p, n);
    else if ((c->st == ST_READY || c->st == ST_ADMIN) && type == T_NEWCHAT)
        on_newchat(c, p, n);
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
    upload_abort(c);
    if (c->dl_fd >= 0)
        close(c->dl_fd);
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
        c->up_fd = c->dl_fd = -1;
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

/* The web client's files: ./web in the source tree, else ../share/hush/web
 * relative to this binary, where `make install` puts them. */
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

static void cmd_newkey(const char *label)
{
    if (!label || !name_valid(label, strlen(label)))
        die("give the chat a name: 1-24 of A-Z a-z 0-9 _ . -   e.g. hushd newkey friends");
    keys_load();
    if (room_by_label(label))
        die("there is already a key called %s (hushd revoke %s to replace it)", label, label);
    char key[HUSH_KEY_CHARS + HUSH_KEY_CHARS / 4];
    uint8_t token[32];
    struct room r = { 0 };
    chat_key_new(key);
    if (chat_key_derive(key, strlen(key), token, NULL) != 0)
        die("not enough memory to derive the key (Argon2id needs 128 MB)");
    chat_verifier(token, r.hash);
    strcpy(r.label, label);
    room_add(&r);
    file_replace(keys_path, keys_write);
    printf("New key for the chat \"%s\":\n\n    %s\n\n"
           "Give it to the people you want in this chat. Anyone who has it can join\n"
           "and read the chat's history. It is not stored anywhere (the server keeps\n"
           "only a hash), so this is the only time it's shown. A running hushd picks\n"
           "it up by itself.\n",
           label, key);
    sodium_memzero(key, sizeof key);
    sodium_memzero(token, sizeof token);
}

/* Delete a chat's messages and images (and, with members, its member list). */
static void delete_history(const uint8_t *room, int members)
{
    sqlite3_stmt *s;
    db_exec("BEGIN IMMEDIATE");
    if (sqlite3_prepare_v2(db, "SELECT id FROM blobs WHERE room = ?1", -1, &s, NULL) != SQLITE_OK)
        die("database: %s", sqlite3_errmsg(db));
    sqlite3_bind_blob(s, 1, room, 32, SQLITE_STATIC);
    while (sqlite3_step(s) == SQLITE_ROW) {
        char path[128];
        if (sqlite3_column_bytes(s, 0) != HUSH_BLOB_ID)
            continue;
        blob_path(sqlite3_column_blob(s, 0), path, sizeof path);
        unlink(path);
    }
    sqlite3_finalize(s);
    static const char *const del[] = { "DELETE FROM blobs WHERE room = ?1",
                                       "DELETE FROM messages WHERE room = ?1",
                                       "DELETE FROM members WHERE room = ?1" };
    for (int i = 0; i < (members ? 3 : 2); i++) {
        if (sqlite3_prepare_v2(db, del[i], -1, &s, NULL) != SQLITE_OK)
            die("database: %s", sqlite3_errmsg(db));
        sqlite3_bind_blob(s, 1, room, 32, SQLITE_STATIC);
        if (sqlite3_step(s) != SQLITE_DONE)
            die("database: %s", sqlite3_errmsg(db));
        sqlite3_finalize(s);
    }
    db_exec("COMMIT");
}

static void cmd_keys(void)
{
    keys_load();
    if (!nrooms)
        printf("no keys yet; create one with: hushd newkey NAME\n");
    sqlite3_stmt *s;
    if (sqlite3_prepare_v2(db,
                           "SELECT (SELECT count(*) FROM messages WHERE room = ?1),"
                           " (SELECT count(*) FROM blobs WHERE room = ?1),"
                           " (SELECT coalesce(sum(size), 0) FROM blobs WHERE room = ?1)",
                           -1, &s, NULL) != SQLITE_OK)
        die("database: %s", sqlite3_errmsg(db));
    for (size_t i = 0; i < nrooms; i++) {
        if (rooms[i].old) {
            printf("%-24s  old key from before this version: hushd revoke %s, then newkey\n",
                   rooms[i].label, rooms[i].label);
            continue;
        }
        sqlite3_reset(s);
        sqlite3_bind_blob(s, 1, rooms[i].hash, 32, SQLITE_STATIC);
        if (sqlite3_step(s) == SQLITE_ROW)
            printf("%-24s  %lld messages, %lld images (%.1f MB)\n", rooms[i].label,
                   sqlite3_column_int64(s, 0), sqlite3_column_int64(s, 1),
                   (double)sqlite3_column_int64(s, 2) / 1048576.0);
    }
    sqlite3_finalize(s);
}

static void cmd_revoke(const char *label)
{
    keys_load();
    struct room *r = label ? room_by_label(label) : NULL;
    if (!r)
        die("no key called %s (see hushd keys)", label ? label : "?");
    uint8_t hash[32];
    memcpy(hash, r->hash, sizeof hash);
    *r = rooms[--nrooms];
    file_replace(keys_path, keys_write);
    delete_history(hash, 1);
    printf("revoked %s and deleted its history; a running hushd disconnects everyone in it\n", label);
}

static void cmd_clear(const char *label)
{
    keys_load();
    struct room *r = label ? room_by_label(label) : NULL;
    if (!r)
        die("no key called %s (see hushd keys)", label ? label : "?");
    delete_history(r->hash, 0);
    printf("deleted every message and image in %s; the key still works\n", label);
}

static void cmd_forget(const char *name)
{
    users_load();
    struct user *u = name ? user_find(name) : NULL;
    if (!u)
        die("no user called %s", name ? name : "?");
    *u = users[--nusers];
    file_replace(users_path, users_write);
    sqlite3_stmt *s;
    if (sqlite3_prepare_v2(db, "DELETE FROM members WHERE name = ?1", -1, &s, NULL) != SQLITE_OK)
        die("database: %s", sqlite3_errmsg(db));
    sqlite3_bind_text(s, 1, name, -1, SQLITE_STATIC);
    sqlite3_step(s);
    sqlite3_finalize(s);
    printf("forgot %s; the next person to log in with that name gets it\n", name);
}

static struct room *room_or_die(const char *label)
{
    keys_load();
    struct room *r = label ? room_by_label(label) : NULL;
    if (!r || r->old)
        die("no chat called %s (see hushd keys)", label ? label : "?");
    return r;
}

static void print_fingerprint(const uint8_t fp[16])
{
    char hex[33];
    sodium_bin2hex(hex, sizeof hex, fp, 16);
    for (int i = 0; i < 32; i += 4)
        printf("%s%.4s", i ? " " : "", hex + i);
}

static void cmd_admin(const char *text, int add)
{
    uint8_t fp[16];
    if (!text || fingerprint_parse(text, fp) != 0)
        die("give a fingerprint as shown on the login page, e.g. hushd admin \"6937 b1d5 ... f284\"");
    admins_load();
    size_t i = 0;
    while (i < nadmins && sodium_memcmp(admins[i], fp, 16))
        i++;
    if (add && i < nadmins)
        die("that key is already an admin");
    if (!add && i == nadmins)
        die("that key isn't an admin (see hushd admins)");
    if (add) {
        void *p = realloc(admins, (nadmins + 1) * sizeof *admins);
        if (!p)
            die("out of memory");
        admins = p;
        memcpy(admins[nadmins++], fp, 16);
    } else {
        memcpy(admins[i], admins[--nadmins], 16);
    }
    file_replace(admins_path, admins_write);
    if (add)
        printf("added: that key is now an admin in every chat, skips the waitlist and can let people in\n");
    else
        printf("removed: that key is no longer an admin\n");
}

static void cmd_admins(void)
{
    admins_load();
    users_load();
    if (!nadmins)
        printf("no admins yet; add yourself with: hushd admin \"YOUR FINGERPRINT\"\n");
    for (size_t i = 0; i < nadmins; i++) {
        print_fingerprint(admins[i]);
        for (size_t j = 0; j < nusers; j++) {
            uint8_t fp[16];
            crypto_generichash(fp, sizeof fp, users[j].pk, sizeof users[j].pk, NULL, 0);
            if (!sodium_memcmp(fp, admins[i], 16))
                printf("  %s", users[j].name);
        }
        printf("\n");
    }
}

static void cmd_pending(void)
{
    keys_load();
    users_load();
    int any = 0;
    for (size_t i = 0; i < nrooms; i++) {
        if (rooms[i].old)
            continue;
        sqlite3_stmt *s = q(Q_WAITING);
        sqlite3_bind_blob(s, 1, rooms[i].hash, 32, SQLITE_STATIC);
        while (sqlite3_step(s) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(s, 0);
            const struct user *u = name ? user_find(name) : NULL;
            if (!u)
                continue;
            uint8_t fp[16];
            crypto_generichash(fp, sizeof fp, u->pk, sizeof u->pk, NULL, 0);
            printf("%-24s  %-24s  ", rooms[i].label, u->name);
            print_fingerprint(fp);
            printf("\n");
            any = 1;
        }
        sqlite3_reset(s);
    }
    if (!any)
        printf("nobody is waiting\n");
}

static void cmd_decide(const char *label, const char *name, int approve)
{
    struct room *r = room_or_die(label);
    int state = name ? member_state(r->hash, name) : MEMBER_NONE;
    if (state != MEMBER_WAITING && !(approve && state == MEMBER_DENIED))
        die("%s isn't waiting to join %s (see hushd pending)", name ? name : "?", label);
    set_member_state(r->hash, name, approve ? MEMBER_IN : MEMBER_DENIED);
    printf("%s %s; if they're waiting right now, they find out within a second\n", name,
           approve ? "is in" : "was turned away");
}

/* The chat key, from $HUSH_KEY or asked for on the terminal without echo. */
static void read_chat_key(char *out, size_t n)
{
    const char *env = getenv("HUSH_KEY");
    if (env && *env) {
        snprintf(out, n, "%s", env);
        return;
    }
    if (!isatty(STDIN_FILENO))
        die("give the chat key in HUSH_KEY");
    struct termios t, off;
    int hide = tcgetattr(STDIN_FILENO, &t) == 0;
    fputs("chat key: ", stderr);
    if (hide) {
        off = t;
        off.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &off);
    }
    char *ok = fgets(out, (int)n, stdin);
    if (hide)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    fputc('\n', stderr);
    if (!ok)
        die("no chat key given");
    out[strcspn(out, "\r\n")] = '\0';
}

static void iso_time(uint64_t ms, char *out, size_t n, int local)
{
    time_t t = (time_t)(ms / 1000);
    struct tm tm;
    if (local)
        localtime_r(&t, &tm);
    else
        gmtime_r(&t, &tm);
    strftime(out, n, local ? "%Y-%m-%d %H:%M" : "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* Text for messages.txt: control characters become spaces. */
static void txt_write(FILE *f, const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        fputc(s[i] < 0x20 || s[i] == 0x7f ? ' ' : s[i], f);
}

/* Decrypt a chat's messages and images with its key, into dir. DMs can't
 * be read with the chat key, so they're listed without their contents. */
static void cmd_export(const char *label, const char *dir)
{
    struct room *r = room_or_die(label);
    if (!dir)
        die("give a new directory to export into: hushd export CHAT DIR");
    users_load();
    char key[HUSH_KEY_MAX + 2];
    uint8_t token[32], chat_key[32], chat_id[32], check[32];
    read_chat_key(key, sizeof key);
    int bad = chat_key_derive(key, strlen(key), token, chat_key);
    if (bad == -2)
        die("not enough memory to derive the key (Argon2id needs 128 MB)");
    if (bad)
        die("that isn't a chat key");
    sodium_memzero(key, sizeof key);
    chat_verifier(token, check);
    if (sodium_memcmp(check, r->hash, 32))
        die("that isn't the key for %s", label);
    crypto_generichash(chat_id, sizeof chat_id, chat_key, sizeof chat_key, NULL, 0);

    char path[4200];
    if (mkdir(dir, 0700) < 0)
        die("cannot create %s: %s (give a new directory)", dir, strerror(errno));
    snprintf(path, sizeof path, "%s/images", dir);
    if (mkdir(path, 0700) < 0)
        die("cannot create %s: %s", path, strerror(errno));
    snprintf(path, sizeof path, "%s/messages.json", dir);
    FILE *js = fopen(path, "w");
    snprintf(path, sizeof path, "%s/messages.txt", dir);
    FILE *tx = fopen(path, "w");
    if (!js || !tx)
        die("cannot write in %s: %s", dir, strerror(errno));

    char when[64];
    iso_time(now_ms(), when, sizeof when, 0);
    fprintf(js, "{\n  \"chat\": ");
    json_string(js, (const uint8_t *)label, strlen(label));
    fprintf(js, ",\n  \"exported\": \"%s\",\n  \"messages\": [", when);
    fprintf(tx, "hush chat \"%s\", exported %s\n\n", label, when);

    sqlite3_stmt *s;
    if (sqlite3_prepare_v2(db, "SELECT id, time, sender, recipient, body FROM messages WHERE room = ?1 ORDER BY id",
                           -1, &s, NULL) != SQLITE_OK)
        die("database: %s", sqlite3_errmsg(db));
    sqlite3_bind_blob(s, 1, r->hash, 32, SQLITE_STATIC);
    static uint8_t plain[HUSH_MAX_FRAME];
    long count = 0, images = 0, unreadable = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {
        long long id = sqlite3_column_int64(s, 0);
        const char *from = (const char *)sqlite3_column_text(s, 2);
        const char *to = (const char *)sqlite3_column_text(s, 3);
        const uint8_t *body = sqlite3_column_blob(s, 4);
        size_t bl = (size_t)sqlite3_column_bytes(s, 4);
        if (!from)
            continue;
        iso_time((uint64_t)sqlite3_column_int64(s, 1), when, sizeof when, 1);
        fprintf(js, "%s\n    {\"id\": %lld, \"from\": ", count++ ? "," : "", id);
        json_string(js, (const uint8_t *)from, strlen(from));
        if (to) {
            fprintf(js, ", \"to\": ");
            json_string(js, (const uint8_t *)to, strlen(to));
            iso_time((uint64_t)sqlite3_column_int64(s, 1), when, sizeof when, 0);
            fprintf(js, ", \"stored\": \"%s\", \"dm\": \"end-to-end encrypted, not readable with the chat key\"}", when);
            iso_time((uint64_t)sqlite3_column_int64(s, 1), when, sizeof when, 1);
            fprintf(tx, "%s  %s -> %s: [private message; can't be read with the chat key]\n", when, from, to);
            continue;
        }
        struct hush_msg m;
        long pl = body && bl <= sizeof plain ? msg_decrypt(body, bl, chat_key, NULL, plain) : -1;
        if (pl < 0 || msg_parse(plain, (size_t)pl, &m) != 0 || strcmp(m.from, from) || *m.to) {
            fprintf(js, ", \"error\": \"could not be decrypted\"}");
            fprintf(tx, "%s  %s: [could not be decrypted]\n", when, from);
            unreadable++;
            continue;
        }
        const struct user *u = user_find(from);
        const char *sig = !u ? "unknown sender" : msg_verify(plain, &m, chat_id, u->pk) == 0 ? "valid" : "INVALID";
        iso_time(m.time, when, sizeof when, 0);
        fprintf(js, ", \"time\": \"%s\", \"signature\": \"%s\"", when, sig);
        iso_time(m.time, when, sizeof when, 1);
        fprintf(tx, "%s  %s: ", when, from);
        struct hush_image im;
        if (m.kind == KIND_TEXT) {
            fprintf(js, ", \"text\": ");
            json_string(js, m.content, m.content_len);
            txt_write(tx, m.content, m.content_len);
        } else if (m.kind == KIND_IMAGE && image_parse(m.content, m.content_len, &im) == 0) {
            char file[64], bp[128];
            snprintf(file, sizeof file, "images/%lld.%s", id, image_ext(im.mime));
            blob_path(im.blob, bp, sizeof bp);
            struct buf enc = { 0 };
            FILE *bf = fopen(bp, "rb");
            size_t got;
            if (bf) {
                do {
                    buf_reserve(&enc, 1 << 20);
                    got = fread(enc.data + enc.len, 1, enc.cap - enc.len, bf);
                    enc.len += got;
                } while (got > 0 && enc.len <= HUSH_MAX_IMAGE + MSG_NONCE + MSG_MAC);
                fclose(bf);
            }
            uint8_t *img = enc.len >= MSG_NONCE + MSG_MAC ? malloc(enc.len) : NULL;
            unsigned long long il;
            snprintf(path, sizeof path, "%s/%s", dir, file);
            FILE *out = NULL;
            if (img && crypto_aead_xchacha20poly1305_ietf_decrypt(img, &il, NULL, enc.data + MSG_NONCE,
                                                                  enc.len - MSG_NONCE, NULL, 0, enc.data,
                                                                  im.file_key) == 0 &&
                (out = fopen(path, "wb")) && fwrite(img, 1, (size_t)il, out) == il && fclose(out) == 0) {
                fprintf(js, ", \"image\": \"%s\"", file);
                fprintf(tx, "[image %s]", file);
                images++;
            } else {
                if (out)
                    fclose(out);
                fprintf(js, ", \"image\": null, \"error\": \"image missing or could not be decrypted\"");
                fprintf(tx, "[image missing]");
            }
            free(img);
            buf_free(&enc);
            fprintf(js, ", \"caption\": ");
            json_string(js, im.caption, im.caption_len);
            if (im.caption_len)
                fputc(' ', tx);
            txt_write(tx, im.caption, im.caption_len);
        } else {
            fprintf(js, ", \"error\": \"unknown kind of message\"");
            fprintf(tx, "[unknown kind of message]");
        }
        fprintf(js, "}");
        fprintf(tx, "%s\n", strcmp(sig, "INVALID") ? "" : "  (signature NOT valid)");
    }
    sqlite3_finalize(s);
    fprintf(js, "\n  ]\n}\n");
    if (fclose(js) != 0 || fclose(tx) != 0)
        die("cannot write in %s: %s", dir, strerror(errno));
    sodium_memzero(chat_key, sizeof chat_key);
    printf("exported %ld messages and %ld images to %s", count, images, dir);
    if (unreadable)
        printf(" (%ld couldn't be decrypted)", unreadable);
    printf("\nThat folder is the chat in readable form: copy it somewhere safe and delete it from the server.\n");
}

static void usage(void)
{
    fprintf(stderr,
            "usage: hushd [options]              run the server\n"
            "       hushd [options] newkey NAME  create a key for a new chat called NAME\n"
            "       hushd [options] keys         list chats and how much they store\n"
            "       hushd [options] clear NAME   delete a chat's messages and images, keep the key\n"
            "       hushd [options] revoke NAME  delete a chat: its key, messages and images\n"
            "       hushd [options] forget USER  free up a name (e.g. a friend lost their key)\n"
            "       hushd [options] admin FP     make the identity key with fingerprint FP an admin\n"
            "       hushd [options] unadmin FP   ...or not any more\n"
            "       hushd [options] admins       list admins\n"
            "       hushd [options] pending      who's waiting to join which chat\n"
            "       hushd [options] approve CHAT USER, deny CHAT USER\n"
            "       hushd [options] export CHAT DIR   decrypt a chat into DIR (asks for its key)\n"
            "options:\n"
            "  -C dir        work in dir: keys, users, database and images live there\n"
            "  -p port       port for terminal clients (default " HUSH_DEFAULT_PORT ")\n"
            "  -w port       port for the web client, 0 for none (default " HUSH_DEFAULT_WEB ")\n"
            "  -d dir        web client files (default ./web, else ../share/hush/web from hushd)\n"
            "  -x            trust X-Forwarded-For from a reverse proxy on this machine\n"
            "files, relative to -C: %s (chat key hashes), %s, %s, %s, %s/\n",
            keys_path, users_path, admins_path, db_path, blob_dir);
    exit(2);
}

int main(int argc, char **argv)
{
    const char *port = HUSH_DEFAULT_PORT, *web_port = HUSH_DEFAULT_WEB, *web_dir = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "C:p:w:d:xh")) != -1) {
        if (opt == 'C') {
            if (chdir(optarg) < 0)
                die("cannot use %s: %s", optarg, strerror(errno));
        } else if (opt == 'p')
            port = optarg;
        else if (opt == 'w')
            web_port = optarg;
        else if (opt == 'd')
            web_dir = optarg;
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
        const char *arg2 = optind + 2 < argc ? argv[optind + 2] : NULL;
        int nargs = argc - optind - 1;
        if (!strcmp(cmd, "admin") || !strcmp(cmd, "unadmin")) {
            /* the fingerprint may come quoted or as eight separate groups */
            static char fp[128];
            for (int i = optind + 1; i < argc && strlen(fp) + strlen(argv[i]) + 2 < sizeof fp; i++)
                strcat(strcat(fp, *fp ? " " : ""), argv[i]);
            cmd_admin(fp, !strcmp(cmd, "admin"));
            return 0;
        }
        if (nargs > 2 || (nargs == 2 && strcmp(cmd, "approve") && strcmp(cmd, "deny") && strcmp(cmd, "export")))
            usage();
        if (!strcmp(cmd, "newkey")) {
            cmd_newkey(arg);
            return 0;
        }
        db_open();
        if (!strcmp(cmd, "keys") && !arg)
            cmd_keys();
        else if (!strcmp(cmd, "admins") && !arg)
            cmd_admins();
        else if (!strcmp(cmd, "pending") && !arg)
            cmd_pending();
        else if ((!strcmp(cmd, "approve") || !strcmp(cmd, "deny")) && arg2)
            cmd_decide(arg, arg2, !strcmp(cmd, "approve"));
        else if (!strcmp(cmd, "export") && arg2)
            cmd_export(arg, arg2);
        else if (!strcmp(cmd, "revoke"))
            cmd_revoke(arg);
        else if (!strcmp(cmd, "clear"))
            cmd_clear(arg);
        else if (!strcmp(cmd, "forget"))
            cmd_forget(arg);
        else
            usage();
        return 0;
    }

    signal(SIGPIPE, SIG_IGN);
    db_open();
    users_load();
    keys_load();
    admins_load();
    file_changed(users_path, &users_st);
    file_changed(keys_path, &keys_st);
    file_changed(admins_path, &admins_st);

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
    note("hushd: %zu chats in %s, %zu registered users in %s, %zu admins", nrooms, keys_path, nusers,
         users_path, nadmins);
    if (!nadmins)
        note("hushd: no admins yet, so nobody can approve new people; see hushd admin");
    for (size_t i = 0; i < nrooms; i++)
        if (rooms[i].old)
            note("hushd: the key for %s is from an older version and no longer works; "
                 "run: hushd revoke %s && hushd newkey %s", rooms[i].label, rooms[i].label, rooms[i].label);
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
        if (poll(pfds, (nfds_t)n, 1000) < 0) {
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
            if (!c->dead && (c->dl_fd >= 0 || c->fetch_n))
                pump_downloads(c);
        }

        /* Pick up `hushd newkey/revoke/forget/admin/approve` run while we're up. */
        if (file_changed(users_path, &users_st))
            users_load();
        if (file_changed(admins_path, &admins_st)) {
            admins_load();
            for (int i = 0; i < MAX_CLIENTS; i++)
                if (clients[i] && clients[i]->st == ST_READY)
                    clients[i]->admin = is_admin(clients[i]->pk);
        }
        for (int i = 0; i < MAX_CLIENTS; i++)
            if (clients[i] && !clients[i]->dead && clients[i]->st == ST_WAITING)
                recheck_waiting(clients[i]);
        if (file_changed(keys_path, &keys_st)) {
            keys_load();
            note("hushd: reloaded %s (%zu chats)", keys_path, nrooms);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                struct client *c = clients[i];
                if (c && !c->no_chat && (c->st == ST_AUTH || c->st == ST_WAITING || c->st == ST_READY) &&
                    !room_find(c->room))
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
