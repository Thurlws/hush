/* Load test for hushd: N clients log in over TCP, then each posts M messages, and every
 * message goes to everyone in the chat. Prints login time, delivery rate and latency.
 * It starts its own hushd in a fresh folder, so it never touches real data.
 *
 *   bench/bench [-n clients] [-m messages each] [-r per second, 0 for all at once] [-s body bytes]
 *               [-t folder for the server's files, bench/ by default]
 *
 * Clients spread over 127.0.0.1-32 to stay under the 16 connections allowed per address.
 * Their identities go in the admin list so nobody waits for approval. Bodies are random,
 * since the server can't read them anyway, with the send time in the first 8 bytes. */
#include "proto.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PORT     17970
#define PORT_STR "17970"
#define MAX_N    600

enum { HELLO_SENT, AUTH_SENT, READY, REFUSED };

struct client {
    int fd, state, sent;
    uint8_t pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    struct buf in, out;
};

static struct client cl[MAX_N];
static double *lat;
static size_t nlat, cap;

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int cmp(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static long num(const char *s, long lo, long hi, const char *what)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (!*s || *end || v < lo || v > hi)
        die("%s should be %ld to %ld", what, lo, hi);
    return v;
}

/* hushd -C dir args..., with stderr to dir/server.log. Returns its pid, or with out set,
 * waits for it and reads its stdout into out. */
static pid_t hushd(const char *dir, const char *const args[], char *out, size_t n)
{
    int fds[2];
    if (out && pipe(fds) < 0)
        die("pipe: %s", strerror(errno));
    pid_t pid = fork();
    if (pid == 0) {
        char log[512];
        snprintf(log, sizeof log, "%s/server.log", dir);
        int fd = open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd >= 0)
            dup2(fd, 2);
        if (out)
            dup2(fds[1], 1);
        char *argv[12] = { "hushd", "-C", (char *)dir };
        for (int i = 0; args[i] && i < 8; i++)
            argv[3 + i] = (char *)args[i];
        execv("./hushd", argv);
        _exit(127);
    }
    if (!out)
        return pid;
    close(fds[1]);
    size_t got = 0;
    ssize_t r;
    while (got + 1 < n && (r = read(fds[0], out + got, n - 1 - got)) > 0)
        got += (size_t)r;
    out[got] = '\0';
    close(fds[0]);
    waitpid(pid, NULL, 0);
    return pid;
}

static void remove_dir(const char *dir)
{
    char path[512], blobs[512];
    snprintf(blobs, sizeof blobs, "%s/blobs", dir);
    const char *dirs[] = { blobs, dir };
    for (size_t i = 0; i < 2; i++) {
        DIR *d = opendir(dirs[i]);
        if (!d)
            continue;
        for (struct dirent *e; (e = readdir(d));) {
            snprintf(path, sizeof path, "%s/%s", dirs[i], e->d_name);
            unlink(path);
        }
        closedir(d);
        rmdir(dirs[i]);
    }
}

static void on_frame(struct client *c, uint8_t type, const uint8_t *p, size_t n)
{
    struct buf b = { 0 };
    if (type == T_ERROR) {
        c->state = REFUSED;
    } else if (c->state == HELLO_SENT && type == T_CHALLENGE && n == HUSH_CHALLENGE_LEN) {
        uint8_t msg[sizeof HUSH_AUTH_CONTEXT - 1 + HUSH_CHALLENGE_LEN], sig[crypto_sign_BYTES];
        memcpy(msg, HUSH_AUTH_CONTEXT, sizeof HUSH_AUTH_CONTEXT - 1);
        memcpy(msg + sizeof HUSH_AUTH_CONTEXT - 1, p, HUSH_CHALLENGE_LEN);
        crypto_sign_detached(sig, NULL, msg, sizeof msg, c->sk);
        buf_put(&b, sig, sizeof sig);
        frame_put(&c->out, T_AUTH, b.data, b.len);
        c->state = AUTH_SENT;
    } else if (c->state == AUTH_SENT && type == T_WELCOME) {
        c->state = READY;
    } else if (c->state == READY && type == T_MSG && n > 17) {
        char from[HUSH_NAME_MAX + 1], to[HUSH_NAME_MAX + 1];
        int k1 = name_get(p + 17, n - 17, from);
        int k2 = k1 < 0 ? -1 : name_get_opt(p + 17 + k1, n - 17 - (size_t)k1, to);
        size_t off = 17 + (size_t)k1 + (size_t)k2;
        if (k2 >= 0 && n >= off + 8 && nlat < cap)
            lat[nlat++] = now() - (double)get_u64(p + off) / 1e9;
    }
    buf_free(&b);
}

int main(int argc, char **argv)
{
    int n = 16, m = 20, opt;
    double rate = 0;
    size_t size = 200;
    const char *parent = "bench";
    while ((opt = getopt(argc, argv, "n:m:r:s:t:")) != -1) {
        if (opt == 'n')
            n = (int)num(optarg, 1, MAX_N, "-n");
        else if (opt == 'm')
            m = (int)num(optarg, 1, 100000, "-m");
        else if (opt == 'r')
            rate = (double)num(optarg, 0, 1000, "-r");
        else if (opt == 's')
            size = (size_t)num(optarg, 104, 4280, "-s");
        else if (opt == 't')
            parent = optarg;
        else
            die("usage: bench/bench [-n clients] [-m messages each] [-r per second] [-s body bytes] [-t folder]");
    }
    if (rate <= 0 && m > 60)
        die("more than 60 messages at once trips hushd's rate limit, add -r 5");
    if (sodium_init() < 0)
        die("libsodium failed to initialise");
    signal(SIGPIPE, SIG_IGN);

    char dir[400], out[1024], key[64] = "", path[512];
    snprintf(dir, sizeof dir, "%s/run-XXXXXX", parent);
    if (!mkdtemp(dir))
        die("mkdtemp: %s", strerror(errno));
    const char *newkey[] = { "newkey", "bench", NULL };
    hushd(dir, newkey, out, sizeof out);
    for (char *l = strtok(out, "\n"); l; l = strtok(NULL, "\n"))
        if (sscanf(l, "    %63s", key) == 1 && strlen(key) == 9)
            break;
    uint8_t token[32];
    if (strlen(key) != 9 || chat_key_derive(key, strlen(key), token, NULL) != 0)
        die("hushd newkey failed (run from the repo root after make)");

    snprintf(path, sizeof path, "%s/hushd-admins.txt", dir);
    FILE *admins = fopen(path, "w");
    if (!admins)
        die("cannot write %s", path);
    for (int i = 0; i < n; i++) {
        uint8_t fp[16];
        char hex[33];
        crypto_sign_keypair(cl[i].pk, cl[i].sk);
        crypto_generichash(fp, sizeof fp, cl[i].pk, sizeof cl[i].pk, NULL, 0);
        fprintf(admins, "%s\n", sodium_bin2hex(hex, sizeof hex, fp, sizeof fp));
    }
    fclose(admins);

    const char *serve[] = { "-p", PORT_STR, "-w", "0", NULL };
    pid_t srv = hushd(dir, serve, NULL, 0);
    nanosleep(&(struct timespec){ .tv_nsec = 300000000 }, NULL);

    /* everyone connects and says hello at once */
    double t0 = now();
    for (int i = 0; i < n; i++) {
        struct client *c = &cl[i];
        struct sockaddr_in src = { .sin_family = AF_INET }, dst = { .sin_family = AF_INET, .sin_port = htons(PORT) };
        src.sin_addr.s_addr = htonl(0x7f000001u + (uint32_t)(i / 16));
        dst.sin_addr.s_addr = htonl(0x7f000001u);
        c->fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (c->fd < 0 || bind(c->fd, (struct sockaddr *)&src, sizeof src) < 0 ||
            connect(c->fd, (struct sockaddr *)&dst, sizeof dst) < 0)
            die("connect %d: %s", i, strerror(errno));
        fcntl(c->fd, F_SETFL, O_NONBLOCK);
        int one = 1;
        setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        struct buf b = { 0 };
        char name[16];
        uint8_t version = HUSH_PROTO;
        snprintf(name, sizeof name, "bench%03d", i);
        name_put(&b, name);
        buf_put(&b, c->pk, sizeof c->pk);
        buf_put(&b, token, sizeof token);
        buf_put(&b, &version, 1);
        frame_put(&c->out, T_HELLO, b.data, b.len);
        buf_free(&b);
    }

    cap = (size_t)n * (size_t)n * (size_t)m;
    lat = calloc(cap, sizeof *lat);
    if (!lat)
        die("out of memory");
    int ready = 0, refused = 0, posting = 0;
    double t1 = 0, t2 = 0, deadline = t0 + 120;
    static struct pollfd pfd[MAX_N];
    static uint8_t body[4280];
    while (now() < deadline) {
        if (!posting && ready + refused == n) {
            posting = 1;
            t1 = now();
        }
        if (posting && nlat >= (size_t)ready * (size_t)ready * (size_t)m) {
            t2 = now();
            break;
        }
        for (int i = 0; posting && i < n; i++) {
            struct client *c = &cl[i];
            while (c->state == READY && c->sent < m && (rate <= 0 || now() >= t1 + c->sent / rate)) {
                struct buf b = { 0 };
                randombytes_buf(body, size);
                put_u64(body, (uint64_t)(now() * 1e9));
                name_put(&b, "");
                buf_put(&b, body, size);
                frame_put(&c->out, T_POST, b.data, b.len);
                buf_free(&b);
                c->sent++;
            }
        }
        for (int i = 0; i < n; i++)
            pfd[i] = (struct pollfd){ .fd = cl[i].state == REFUSED ? -1 : cl[i].fd,
                                      .events = (short)(POLLIN | (cl[i].out.len ? POLLOUT : 0)) };
        if (poll(pfd, (nfds_t)n, 5) < 0 && errno != EINTR)
            die("poll: %s", strerror(errno));
        for (int i = 0; i < n; i++) {
            struct client *c = &cl[i];
            int was = c->state;
            if (pfd[i].revents & POLLOUT) {
                ssize_t w = send(c->fd, c->out.data, c->out.len, MSG_NOSIGNAL);
                if (w > 0)
                    buf_consume(&c->out, (size_t)w);
            }
            if (pfd[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                buf_reserve(&c->in, 65536);
                ssize_t r = recv(c->fd, c->in.data + c->in.len, c->in.cap - c->in.len, 0);
                if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR))
                    c->state = REFUSED;
                if (r > 0)
                    c->in.len += (size_t)r;
                uint8_t type;
                const uint8_t *fp;
                size_t len, fs;
                while (c->state != REFUSED && frame_peek(&c->in, &type, &fp, &len, &fs) == 1) {
                    on_frame(c, type, fp, len);
                    buf_consume(&c->in, fs);
                }
            }
            ready += (c->state == READY) - (was == READY);
            refused += c->state == REFUSED && was != REFUSED;
        }
    }
    double t_login = t1 > 0 ? t1 - t0 : now() - t0;
    if (t2 <= 0)
        t2 = now();

    kill(srv, SIGTERM);
    waitpid(srv, NULL, 0);
    remove_dir(dir);

    qsort(lat, nlat, sizeof *lat, cmp);
    double secs = t2 - t1;
    size_t want = (size_t)ready * (size_t)ready * (size_t)m;
    printf("%d clients (%d in, %d refused), %d messages each, %zu-byte bodies, %s\n", n, ready, refused, m, size,
           rate > 0 ? "paced" : "all at once");
    printf("  logins %.2f s, %zu of %zu deliveries in %.2f s: %.0f deliveries/s, %.0f messages/s\n",
           t_login, nlat, want, secs, secs > 0 ? (double)nlat / secs : 0, secs > 0 ? (double)ready * m / secs : 0);
    if (nlat)
        printf("  latency p50 %.1f ms, p99 %.1f ms, max %.1f ms\n", lat[nlat / 2] * 1e3, lat[nlat * 99 / 100] * 1e3,
               lat[nlat - 1] * 1e3);
    return nlat == want ? 0 : 1;
}
