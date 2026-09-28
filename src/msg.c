#include "msg.h"

#include <string.h>

long msg_decrypt(const uint8_t *body, size_t n, const uint8_t chat_key[32], const uint8_t *dm_key,
                 uint8_t *out)
{
    if (n < MSG_NONCE + MSG_MAC)
        return -1;
    if (dm_key) {
        if (crypto_box_open_easy_afternm(out, body + MSG_NONCE, n - MSG_NONCE, body, dm_key) != 0)
            return -1;
        return (long)(n - MSG_NONCE - crypto_box_MACBYTES);
    }
    unsigned long long l;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out, &l, NULL, body + MSG_NONCE, n - MSG_NONCE, NULL, 0,
                                                   body, chat_key) != 0)
        return -1;
    return (long)l;
}

int msg_parse(const uint8_t *plain, size_t n, struct hush_msg *m)
{
    if (n < MSG_HEAD + 2 + crypto_sign_BYTES || plain[0] != HUSH_MSG_VERSION)
        return -1;
    size_t signed_len = n - crypto_sign_BYTES;
    int a = name_get(plain + MSG_HEAD, signed_len - MSG_HEAD, m->from);
    if (a < 0)
        return -1;
    int b = name_get_opt(plain + MSG_HEAD + a, signed_len - MSG_HEAD - (size_t)a, m->to);
    if (b < 0)
        return -1;
    m->kind = plain[1];
    m->time = get_u64(plain + 2);
    m->uid = plain + 10;
    m->content = plain + MSG_HEAD + a + b;
    m->content_len = signed_len - MSG_HEAD - (size_t)a - (size_t)b;
    m->signed_len = signed_len;
    return 0;
}

int msg_verify(const uint8_t *plain, const struct hush_msg *m, const uint8_t chat_id[32],
               const uint8_t pk[crypto_sign_PUBLICKEYBYTES])
{
    struct buf d = { 0 };
    buf_put(&d, HUSH_MSG_CONTEXT, sizeof HUSH_MSG_CONTEXT - 1);
    buf_put(&d, chat_id, 32);
    buf_put(&d, plain, m->signed_len);
    int ok = crypto_sign_verify_detached(plain + m->signed_len, d.data, d.len, pk) == 0;
    buf_free(&d);
    return ok ? 0 : -1;
}

/* file key | blob id | u32 size | u16 width | u16 height | u8 len + mime | caption */
int image_parse(const uint8_t *c, size_t n, struct hush_image *im)
{
    if (n < 57 || c[56] == 0 || c[56] >= sizeof im->mime || n < 57u + c[56])
        return -1;
    im->file_key = c;
    im->blob = c + 32;
    im->size = get_u32(c + 48);
    im->width = get_u16(c + 52);
    im->height = get_u16(c + 54);
    memcpy(im->mime, c + 57, c[56]);
    im->mime[c[56]] = '\0';
    im->caption = c + 57 + c[56];
    im->caption_len = n - 57 - c[56];
    return image_ext(im->mime) ? 0 : -1;
}

const char *image_ext(const char *mime)
{
    return !strcmp(mime, "image/jpeg") ? "jpg"
         : !strcmp(mime, "image/png")  ? "png"
         : !strcmp(mime, "image/gif")  ? "gif"
         : !strcmp(mime, "image/webp") ? "webp"
                                       : NULL;
}

void json_string(FILE *f, const uint8_t *s, size_t n)
{
    fputc('"', f);
    for (size_t i = 0; i < n;) {
        uint8_t c = s[i];
        if (c < 0x80) {
            if (c == '"' || c == '\\')
                fprintf(f, "\\%c", c);
            else if (c < 0x20 || c == 0x7f)
                fprintf(f, "\\u%04x", c);
            else
                fputc(c, f);
            i++;
            continue;
        }
        size_t len = c >= 0xC2 && c <= 0xDF ? 2 : c >= 0xE0 && c <= 0xEF ? 3 : c >= 0xF0 && c <= 0xF4 ? 4 : 0;
        int ok = len && i + len <= n;
        for (size_t j = 1; ok && j < len; j++)
            ok = (s[i + j] & 0xC0) == 0x80;
        if (ok && ((c == 0xE0 && s[i + 1] < 0xA0) || (c == 0xED && s[i + 1] >= 0xA0) ||
                   (c == 0xF0 && s[i + 1] < 0x90) || (c == 0xF4 && s[i + 1] >= 0x90)))
            ok = 0;
        if (ok) {
            fwrite(s + i, 1, len, f);
            i += len;
        } else {
            fputs("\xef\xbf\xbd", f); /* U+FFFD */
            i++;
        }
    }
    fputc('"', f);
}
