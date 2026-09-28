/* hushd: relay server. It authenticates users by their signing key and
 * forwards encrypted blobs between them. It never holds a key that can
 * decrypt messages. */
#include "proto.h"

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
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS  256
#define MAX_OUTBUF   (4u << 20)
#define AUTH_TIMEOUT 15 /* seconds a connection may spend in the handshake */

enum cstate { ST_HELLO, ST_AUTH, ST_READY };

struct client {
    int fd;
    enum cstate st;
    int dead;
    time_t since;
    char addr[NI_MAXHOST + NI_MAXSERV + 4];
    char name[HUSH_NAME_MAX + 1];
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t challenge[HUSH_CHALLENGE_LEN];
    struct buf in, out;
};

/* Names are pinned to the first key that claims them, so nobody can take
 * over a friend's name on this server. */
struct user {
    char name[HUSH_NAME_MAX + 1];
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
};

static struct client *clients[MAX_CLIENTS];
static struct user *users;
static size_t nusers;
static const char *users_path = "hushd-users.txt";

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

static struct client *client_find(const char *name)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i] && !clients[i]->dead && clients[i]->st == ST_READY &&
            !strcmp(clients[i]->name, name))
            return clients[i];
    return NULL;
}

static void send_to(struct client *c, uint8_t type, const void *p, size_t n)
{
    if (c->dead)
        return;
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
        c->dead = 1;
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
    if (k < 0 || n - k != crypto_sign_PUBLICKEYBYTES) {
        send_error(c, "bad hello (names are 1-24 of A-Z a-z 0-9 _ . -)", 1);
        return;
    }
    memcpy(c->pk, p + k, sizeof c->pk);
    struct user *u = user_find(c->name);
    if (u && sodium_memcmp(u->pk, c->pk, sizeof c->pk) != 0) {
        send_error(c, "that name belongs to a different key on this server", 1);
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
    if (client_find(c->name)) {
        send_error(c, "that name is already connected", 1);
        return;
    }
    if (!user_find(c->name)) {
        user_pin(c->name, c->pk);
        note("%s: registered new user %s", c->addr, c->name);
    }
    c->st = ST_READY;
    note("%s: %s joined", c->addr, c->name);

    send_to(c, T_WELCOME, NULL, 0);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        struct client *o = clients[i];
        if (!o || o == c || o->dead || o->st != ST_READY)
            continue;
        send_peer(c, o, 0);
        send_peer(o, c, 1);
    }
}

static void on_send(struct client *c, const uint8_t *p, size_t n)
{
    char to[HUSH_NAME_MAX + 1];
    int k = name_get(p, n, to);
    if (k < 0 || n - k < crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
        send_error(c, "malformed message", 1);
        return;
    }
    struct client *dst = client_find(to);
    if (!dst) {
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
    if (c->out.len) /* best effort, so a final error message gets through */
        send(c->fd, c->out.data, c->out.len, MSG_NOSIGNAL | MSG_DONTWAIT);
    close(c->fd);
    if (c->st == ST_READY) {
        note("%s: %s left", c->addr, c->name);
        struct buf b = { 0 };
        name_put(&b, c->name);
        for (int j = 0; j < MAX_CLIENTS; j++)
            if (clients[j] && clients[j]->st == ST_READY)
                send_to(clients[j], T_LEAVE, b.data, b.len);
        buf_free(&b);
    }
    buf_free(&c->in);
    buf_free(&c->out);
    free(c);
}

static void accept_client(int lfd)
{
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
        close(fd);
        return;
    }
    struct client *c = calloc(1, sizeof *c);
    if (!c)
        die("out of memory");
    c->fd = fd;
    c->since = time(NULL);
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    if (getnameinfo((struct sockaddr *)&ss, sl, host, sizeof host, serv, sizeof serv,
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0)
        snprintf(c->addr, sizeof c->addr, "[%s]:%s", host, serv);
    else
        strcpy(c->addr, "?");
    clients[slot] = c;
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
            if (bind(fd, res->ai_addr, res->ai_addrlen) == 0 && listen(fd, 64) == 0) {
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

static void usage(void)
{
    fprintf(stderr, "usage: hushd [-p port] [-u users-file]\n"
                    "  -p port        port to listen on (default " HUSH_DEFAULT_PORT ")\n"
                    "  -u users-file  where name->key registrations are kept (default %s)\n",
            users_path);
    exit(2);
}

int main(int argc, char **argv)
{
    const char *port = HUSH_DEFAULT_PORT;
    int opt;
    while ((opt = getopt(argc, argv, "p:u:h")) != -1) {
        if (opt == 'p')
            port = optarg;
        else if (opt == 'u')
            users_path = optarg;
        else
            usage();
    }
    if (optind != argc)
        usage();
    if (sodium_init() < 0)
        die("libsodium failed to initialise");
    signal(SIGPIPE, SIG_IGN);
    users_load();
    int lfd = listen_on(port);
    note("hushd listening on port %s (%zu registered users in %s)", port, nusers, users_path);

    static struct pollfd pfds[MAX_CLIENTS + 1];
    static int slot_of[MAX_CLIENTS + 1];
    for (;;) {
        int n = 0;
        pfds[n++] = (struct pollfd){ .fd = lfd, .events = POLLIN };
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i])
                continue;
            pfds[n] = (struct pollfd){ .fd = clients[i]->fd,
                                       .events = POLLIN | (clients[i]->out.len ? POLLOUT : 0) };
            slot_of[n++] = i;
        }
        if (poll(pfds, n, 1000) < 0) {
            if (errno == EINTR)
                continue;
            die("poll: %s", strerror(errno));
        }
        if (pfds[0].revents & POLLIN)
            accept_client(lfd);
        for (int k = 1; k < n; k++) {
            struct client *c = clients[slot_of[k]];
            if (!c || c->dead)
                continue;
            if (pfds[k].revents & (POLLIN | POLLHUP | POLLERR))
                client_read(c);
            if (!c->dead && (pfds[k].revents & POLLOUT))
                client_write(c);
        }
        time_t now = time(NULL);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i])
                continue;
            if (clients[i]->st != ST_READY && now - clients[i]->since > AUTH_TIMEOUT)
                clients[i]->dead = 1;
            if (clients[i]->dead)
                client_close(i);
        }
    }
}
