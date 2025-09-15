#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* Derive key from password via PBKDF2-HMAC-SHA256. Returns 0 on success. */
int kdf_pbkdf2_sha256(const char *password,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iters,
                      uint8_t *out_key, size_t out_key_len);

/* AEAD: AES-256-GCM encrypt/decrypt.
   - nonce_len must be 12 (GCM standard).
   - tag_len must be 16.
   Returns 0 on success. */
int aes256gcm_encrypt(const uint8_t *key,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *pt, size_t pt_len,
                      const uint8_t *aad, size_t aad_len,
                      uint8_t *ct,
                      uint8_t *tag, size_t tag_len);

int aes256gcm_decrypt(const uint8_t *key,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *ct, size_t ct_len,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *tag, size_t tag_len,
                      uint8_t *out_pt);

/* Cryptographically secure random bytes. Returns 0 on success. */
int crypto_rand(uint8_t *buf, size_t len);

/* Zeroize secrets. Tries to avoid being optimized out. */
void secure_bzero(void *p, size_t n);

#endif
