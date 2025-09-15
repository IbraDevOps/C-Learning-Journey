#define _POSIX_C_SOURCE 200809L
#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>

int kdf_pbkdf2_sha256(const char *password,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iters,
                      uint8_t *out_key, size_t out_key_len)
{
    if (!password || !salt || !out_key || out_key_len == 0) return -1;
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                          salt, (int)salt_len,
                          (int)iters,
                          EVP_sha256(),
                          (int)out_key_len, out_key) != 1) return -1;
    return 0;
}

int aes256gcm_encrypt(const uint8_t *key,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *pt, size_t pt_len,
                      const uint8_t *aad, size_t aad_len,
                      uint8_t *ct,
                      uint8_t *tag, size_t tag_len)
{
    int ok = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    int outlen = 0;
    if (aad && aad_len) {
        if (EVP_EncryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len) != 1) goto done;
    }
    if (EVP_EncryptUpdate(ctx, ct, &outlen, pt, (int)pt_len) != 1) goto done;
    int ctlen = outlen;

    if (EVP_EncryptFinal_ex(ctx, ct + ctlen, &outlen) != 1) goto done;
    ctlen += outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len, tag) != 1) goto done;

    ok = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int aes256gcm_decrypt(const uint8_t *key,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *ct, size_t ct_len,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *tag, size_t tag_len,
                      uint8_t *out_pt)
{
    int ok = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    int outlen = 0;
    if (aad && aad_len) {
        if (EVP_DecryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len) != 1) goto done;
    }
    if (EVP_DecryptUpdate(ctx, out_pt, &outlen, ct, (int)ct_len) != 1) goto done;
    int ptlen = outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void*)tag) != 1) goto done;

    if (EVP_DecryptFinal_ex(ctx, out_pt + ptlen, &outlen) != 1) goto done;
    ptlen += outlen;

    ok = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int crypto_rand(uint8_t *buf, size_t len) {
    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

void secure_bzero(void *p, size_t n) {
#if defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    volatile unsigned char *vp = (volatile unsigned char*)p;
    while (n--) *vp++ = 0;
#endif
}
