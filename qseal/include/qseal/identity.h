/*
 * qseal/include/qseal/identity.h
 *
 * Device identity provisioning, key storage, fingerprinting, and trust verification.
 * Enforces strict 0600 file permissions and separates private keys from configuration.
 */

#ifndef QSEAL_IDENTITY_H
#define QSEAL_IDENTITY_H

#include "common.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IDENTITY_MAX_KEY_BYTES 4096

typedef struct {
    char device_id[QSEAL_MAX_ID_LEN];
    qseal_mode_t mode;
    
    char private_key_path[QSEAL_MAX_PATH_LEN];
    char public_key_path[QSEAL_MAX_PATH_LEN];
    char trust_store_path[QSEAL_MAX_PATH_LEN];
    
    uint8_t public_key[IDENTITY_MAX_KEY_BYTES];
    size_t  public_key_len;
    
    uint8_t private_key[IDENTITY_MAX_KEY_BYTES];
    size_t  private_key_len;
    
    char fingerprint[65]; /* SHA-256 hex representation */
    bool is_provisioned;
} qseal_identity_t;

/* Initialize and validate paths */
int  qseal_identity_init(qseal_identity_t *ident, const char *device_id,
                         qseal_mode_t mode, const char *base_dir);

/* Generate fresh keypair and write with strict 0600 permissions */
int  qseal_identity_generate(qseal_identity_t *ident);

/* Load existing keypair and verify file integrity and permissions */
int  qseal_identity_load(qseal_identity_t *ident);

/* Trust Store Management: Verify peer public key against pinned store (TOFU supported) */
int  qseal_identity_verify_peer(const qseal_identity_t *ident,
                                const char *peer_id,
                                const uint8_t *peer_pk, size_t peer_pk_len,
                                bool allow_tofu);

/* Check if identity file exists without loading */
bool qseal_identity_exists(const qseal_identity_t *ident);

/* Format fingerprint from raw public key */
int  qseal_identity_compute_fingerprint(const uint8_t *pk, size_t pk_len, char out_hex[65]);

/* Adapt multi-algorithm or composite identity keys to the active operating mode */
int  qseal_identity_adapt_for_mode(qseal_identity_t *ident, qseal_mode_t target_mode);

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
typedef qseal_identity_t securecomm_identity_t;
#define securecomm_identity_init               qseal_identity_init
#define securecomm_identity_generate           qseal_identity_generate
#define securecomm_identity_load               qseal_identity_load
#define securecomm_identity_verify_peer        qseal_identity_verify_peer
#define securecomm_identity_exists             qseal_identity_exists
#define securecomm_identity_compute_fingerprint qseal_identity_compute_fingerprint
#define securecomm_identity_adapt_for_mode     qseal_identity_adapt_for_mode

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_IDENTITY_H */
