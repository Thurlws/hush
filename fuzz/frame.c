/* libFuzzer: TCP frames and the names at the start of most payloads */
#include "proto.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct buf b = { 0 };
    uint8_t type;
    const uint8_t *p;
    size_t n, fs;
    char name[HUSH_NAME_MAX + 1];
    buf_put(&b, data, size);
    while (frame_peek(&b, &type, &p, &n, &fs) == 1) {
        int k = name_get(p, n, name);
        if (k >= 0)
            name_get_opt(p + k, n - (size_t)k, name);
        buf_consume(&b, fs);
    }
    buf_free(&b);
    return 0;
}
