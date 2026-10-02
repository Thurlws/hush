/* libFuzzer: WebSocket frames as a browser would send them, read the way ws_read does */
#include "web.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct buf b = { 0 };
    int op;
    uint8_t *p;
    size_t n, fs;
    buf_put(&b, data, size);
    while (ws_peek(&b, &op, &p, &n, &fs, HUSH_MAX_FRAME) == 1)
        buf_consume(&b, fs);
    buf_free(&b);
    return 0;
}
