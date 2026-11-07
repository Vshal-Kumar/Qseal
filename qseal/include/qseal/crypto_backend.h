/*
 * qseal/include/qseal/crypto_backend.h
 *
 * Generic cryptographic backend abstraction for QSEAL.
 * Interfaces with Pure PQC (liboqs) and Hybrid implementations.
 */

#ifndef QSEAL_CRYPTO_BACKEND_H
#define QSEAL_CRYPTO_BACKEND_H

#include "common.h"
#include "profile_registry.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qseal_crypto_backend_s qseal_crypto_backend_t;

struct qseal_crypto_backend_s {
    const qseal_profile_t *profile;
    void *ctx; /* Backend-specific private context */
    
    int (*init)(qseal_crypto_backend_t *self);
    void (*cleanup)(qseal_crypto_backend_t *self);
    
    /* Key Exchange (KEX) */
    int (*kex_keypair)(qseal_crypto_backend_t *self, uint8_t *public_key, size_t *pk_len,
                       uint8_t *secret_key, size_t *sk_len);
    int (*kex_encapsulate)(qseal_crypto_backend_t *self, const uint8_t *peer_pk, size_t peer_pk_len,
                           uint8_t *ciphertext, size_t *ct_len,
                           uint8_t *shared_secret, size_t *ss_len);
    int (*kex_decapsulate)(qseal_crypto_backend_t *self, const uint8_t *ciphertext, size_t ct_len,
                           const uint8_t *secret_key, size_t sk_len,
                           uint8_t *shared_secret, size_t *ss_len);
    
    /* Digital Signatures (DSA) */
    int (*dsa_keypair)(qseal_crypto_backend_t *self, uint8_t *public_key, size_t *pk_len,
                       uint8_t *secret_key, size_t *sk_len);
    int (*dsa_sign)(qseal_crypto_backend_t *self, const uint8_t *message, size_t msg_len,
                    const uint8_t *secret_key, size_t sk_len,
                    uint8_t *signature, size_t *sig_len);
    int (*dsa_verify)(qseal_crypto_backend_t *self, const uint8_t *message, size_t msg_len,
                      const uint8_t *signature, size_t sig_len,
                      const uint8_t *public_key, size_t pk_len);
    
    /* Key Derivation (KDF) */
    int (*kdf_derive_session_keys)(qseal_crypto_backend_t *self,
                                   const uint8_t *shared_secret, size_t ss_len,
                                   const uint8_t *salt, size_t salt_len,
                                   uint8_t *c2s_key, size_t c2s_key_len,
                                   uint8_t *s2c_key, size_t s2c_key_len);
    
    /* Authenticated Encryption with Associated Data (AEAD) */
    int (*aead_encrypt)(qseal_crypto_backend_t *self,
                        const uint8_t *plaintext, size_t pt_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *key, size_t key_len,
                        uint8_t *ciphertext, size_t *ct_len,
                        uint8_t *tag, size_t tag_len);
    int (*aead_decrypt)(qseal_crypto_backend_t *self,
                        const uint8_t *ciphertext, size_t ct_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *tag, size_t tag_len,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *key, size_t key_len,
                        uint8_t *plaintext, size_t *pt_len);
};

/* Factory function: Allocates and initializes backend for given profile */
qseal_crypto_backend_t *qseal_crypto_backend_create(const qseal_profile_t *profile);
void qseal_crypto_backend_free(qseal_crypto_backend_t *backend);

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
typedef qseal_crypto_backend_t crypto_backend_t;
typedef qseal_crypto_backend_t securecomm_crypto_backend_t;
#define securecomm_crypto_backend_create qseal_crypto_backend_create
#define securecomm_crypto_backend_free   qseal_crypto_backend_free

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_CRYPTO_BACKEND_H */
