/*
 * qseal/include/qseal/profile_registry.h
 *
 * Cryptographic Profile Registry for QSEAL.
 * Decouples algorithm configurations from adaptive selection logic.
 */

#ifndef QSEAL_PROFILE_REGISTRY_H
#define QSEAL_PROFILE_REGISTRY_H

#include "common.h"
#include "device_profile.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROFILE_STATUS_VALIDATED     = 0,
    PROFILE_STATUS_EXPERIMENTAL  = 1,
    PROFILE_STATUS_UNAVAILABLE   = 2
} qseal_profile_status_t;

typedef struct {
    char id[QSEAL_MAX_PROFILE_NAME];            /* e.g. "profile-pqc-1" */
    char name[128];                             /* e.g. "NIST FIPS 203/204 Pure Post-Quantum" */
    qseal_mode_t mode;                          /* CLASSICAL, PQC, HYBRID */
    
    /* Primitive Identifiers */
    char kem_algorithm[64];                     /* e.g. "ML-KEM-768", "X25519" */
    char dsa_algorithm[64];                     /* e.g. "ML-DSA-65", "Ed25519" */
    char aead_algorithm[64];                    /* e.g. "ChaCha20-Poly1305", "AES-128-CCM" */
    char kdf_algorithm[64];                     /* e.g. "SHAKE256", "HKDF-SHA-384" */
    
    /* Protocol Attributes */
    uint16_t protocol_version;                  /* e.g. 0x0100 */
    uint16_t default_port;                      /* standard port (9877, 9879, etc.) */
    
    /* Resource & Security Constraints */
    uint32_t estimated_handshake_bytes;         /* unfragmented or fragmented wire size */
    uint32_t min_ram_mb;                        /* minimal RAM to instantiate */
    uint32_t session_memory_bytes;              /* bytes per active session */
    bool quantum_resistant_kex;                 /* protects secrecy against CRQCs */
    bool quantum_resistant_auth;                /* protects authenticity against CRQCs */
    bool dual_combiner;                         /* hybrid fail-closed design */
    bool fips_standardized;                     /* NIST FIPS standardized */
    
    /* Runtime Status */
    qseal_profile_status_t status;
    bool backend_ready;
} qseal_profile_t;

int qseal_profile_registry_init(void);

const qseal_profile_t *qseal_profile_find(const char *id);
const qseal_profile_t *qseal_profile_default_for_mode(qseal_mode_t mode);

size_t qseal_profile_list_all(const qseal_profile_t ***out_profiles);
const qseal_profile_t *qseal_profile_get_all(size_t *out_count);

bool qseal_profile_is_supported_on_device(const qseal_profile_t *profile,
                                          const qseal_device_profile_t *device,
                                          char *out_reason, size_t reason_max);

void qseal_profile_print(const qseal_profile_t *profile, FILE *out);
void qseal_profile_list_print(FILE *out);

/* Inline Convenience Wrappers */
static inline const qseal_profile_t *qseal_profile_get_by_id(const char *id) {
    return qseal_profile_find(id);
}
static inline const qseal_profile_t *qseal_profile_get_by_mode(qseal_mode_t mode) {
    return qseal_profile_default_for_mode(mode);
}
static inline const qseal_profile_t *qseal_profile_get_default(void) {
    return qseal_profile_default_for_mode(QSEAL_MODE_HYBRID);
}
static inline bool qseal_profile_is_device_compatible(const qseal_profile_t *profile,
                                                      const qseal_device_profile_t *device) {
    return qseal_profile_is_supported_on_device(profile, device, NULL, 0);
}

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
typedef qseal_profile_status_t securecomm_profile_status_t;
typedef qseal_profile_t securecomm_profile_t;

#define securecomm_profile_registry_init qseal_profile_registry_init
#define securecomm_profile_find qseal_profile_find
#define securecomm_profile_default_for_mode qseal_profile_default_for_mode
#define securecomm_profile_list_all qseal_profile_list_all
#define securecomm_profile_get_all qseal_profile_get_all
#define securecomm_profile_is_supported_on_device qseal_profile_is_supported_on_device
#define securecomm_profile_print qseal_profile_print
#define securecomm_profile_list_print qseal_profile_list_print
#define securecomm_profile_get_by_id qseal_profile_get_by_id
#define securecomm_profile_get_by_mode qseal_profile_get_by_mode
#define securecomm_profile_get_default qseal_profile_get_default

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_PROFILE_REGISTRY_H */
