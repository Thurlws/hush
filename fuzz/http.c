/* libFuzzer: the HTTP request parser, and serving or upgrading whatever it accepts */
#include "web.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc, (void)argv;
    return sodium_init() < 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct http_req req;
    struct buf out = { 0 };
    if (http_parse(data, size, &req) > 0) {
        http_serve(&out, &req);
        out.len = 0;
        ws_upgrade(&out, &req);
    }
    buf_free(&out);
    return 0;
}
