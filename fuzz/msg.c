/* libFuzzer: a message body through decryption, and a plaintext through parsing,
 * signature checks, image parsing and JSON output */
#include "msg.h"

static FILE *devnull;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc, (void)argv;
    devnull = fopen("/dev/null", "w");
    return sodium_init() < 0 || !devnull;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t out[HUSH_MAX_FRAME + 64];
    static const uint8_t key[32] = { 1 }, chat_id[32] = { 2 }, pk[crypto_sign_PUBLICKEYBYTES] = { 3 };
    struct hush_msg m;
    struct hush_image im;
    if (size <= sizeof out) {
        msg_decrypt(data, size, key, NULL, out);
        msg_decrypt(data, size, key, key, out);
    }
    if (msg_parse(data, size, &m) == 0) {
        msg_verify(data, &m, chat_id, pk);
        json_string(devnull, m.content, m.content_len);
        if (image_parse(m.content, m.content_len, &im) == 0)
            json_string(devnull, im.caption, im.caption_len);
    }
    return 0;
}
