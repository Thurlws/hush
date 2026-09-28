/* Just enough HTTP/1.1 and WebSocket (RFC 6455) for hushd to serve the
 * web client and carry hush frames to browsers. No knowledge of clients. */
#pragma once

#include "proto.h"

#define HTTP_MAX_HEADER 8192

struct http_req {
    int get;     /* GET or HEAD */
    int head;    /* HEAD: headers only */
    int upgrade; /* Upgrade: websocket */
    char path[64];
    char host[256], origin[256], xff[256];
    char ws_key[64], ws_version[8];
};

/* Parse a request head from buf. Returns the number of bytes it used,
 * 0 if more bytes are needed, or -1 if the request is malformed. */
int http_parse(const uint8_t *buf, size_t len, struct http_req *req);

/* Load the web client's files from dir. Returns -1 and sets errno if one is missing. */
int web_load(const char *dir);
/* Queue the response for a plain (non-upgrade) request. */
void http_serve(struct buf *out, const struct http_req *req);
/* Queue a bodyless error response such as 429 or 400. */
void http_error(struct buf *out, int code);
/* Queue the 101 response for a valid WebSocket upgrade, or an error
 * response. Returns 1 if the connection is now a WebSocket. */
int ws_upgrade(struct buf *out, const struct http_req *req);

enum { WS_TEXT = 1, WS_BINARY = 2, WS_CLOSE = 8, WS_PING = 9, WS_PONG = 10 };

/* 1: a whole frame is buffered and unmasked in place (drop it with
 * buf_consume(b, *frame_size)), 0: need more bytes, -1: protocol error
 * or bigger than max. Fragmented messages are not supported. */
int ws_peek(struct buf *b, int *opcode, uint8_t **payload, size_t *len, size_t *frame_size,
            size_t max);
/* Queue one unmasked frame whose payload is a followed by b. */
void ws_put(struct buf *out, int opcode, const void *a, size_t na, const void *b, size_t nb);
