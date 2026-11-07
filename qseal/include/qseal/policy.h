/*
 * qseal/include/qseal/policy.h
 *
 * Security policy rules, constraints, and objective preferences for QSEAL.
 */

#ifndef QSEAL_POLICY_H
#define QSEAL_POLICY_H

#include "common.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PREF_HIGH_SECURITY  = 0,  /* Prioritize pure PQC or dual-combiner Hybrid */
    PREF_LOW_LATENCY    = 1,  /* Prioritize faster handshake latency */
    PREF_LOW_MEMORY     = 2,  /* Prioritize minimal RAM consumption */
    PREF_BALANCED       = 3   /* Balance quantum-safety with performance */
} qseal_policy_pref_t;

#define QSEAL_PREF_LOW_LATENCY     PREF_LOW_LATENCY
#define QSEAL_PREF_LOW_MEMORY      PREF_LOW_MEMORY
#define QSEAL_PREF_HIGH_THROUGHPUT PREF_LOW_LATENCY
#define QSEAL_PREF_BALANCED        PREF_BALANCED

typedef struct {
    bool require_quantum_resistance;   /* Mandatory quantum-safe key exchange */
    bool require_quantum_auth;         /* Mandatory quantum-safe digital signatures */
    bool require_dual_combiner;        /* Mandatory hybrid defense-in-depth */
    bool allow_classical_fallback;     /* Allow fallback to classical (default: FALSE) */
    bool require_fips_algorithms;      /* Only allow NIST FIPS certified algorithms */
    bool allow_tofu;                   /* Allow Trust-on-First-Use */
    
    uint32_t max_acceptable_latency_ms;/* Maximum acceptable handshake latency */
    uint32_t max_memory_budget_mb;     /* Maximum RAM budget for cryptographic ops */
    uint16_t min_protocol_version;     /* Version floor to prevent downgrade attacks */
    
    qseal_policy_pref_t preference;    /* Optimization goal for ranking */
    qseal_policy_pref_t pref;          /* Alias for preference */
} qseal_policy_t;

void qseal_policy_init_default(qseal_policy_t *policy);
void qseal_policy_init_high_security(qseal_policy_t *policy);
void qseal_policy_init_iot_constrained(qseal_policy_t *policy);

const char *qseal_policy_pref_to_string(qseal_policy_pref_t pref);
qseal_policy_pref_t qseal_policy_pref_from_string(const char *str);

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
typedef qseal_policy_pref_t securecomm_policy_pref_t;
typedef qseal_policy_t securecomm_policy_t;

#define SECURECOMM_PREF_LOW_LATENCY     QSEAL_PREF_LOW_LATENCY
#define SECURECOMM_PREF_LOW_MEMORY      QSEAL_PREF_LOW_MEMORY
#define SECURECOMM_PREF_HIGH_THROUGHPUT QSEAL_PREF_HIGH_THROUGHPUT
#define SECURECOMM_PREF_BALANCED        QSEAL_PREF_BALANCED

#define securecomm_policy_init_default        qseal_policy_init_default
#define securecomm_policy_init_high_security  qseal_policy_init_high_security
#define securecomm_policy_init_iot_constrained qseal_policy_init_iot_constrained
#define securecomm_policy_pref_to_string      qseal_policy_pref_to_string
#define securecomm_policy_pref_from_string    qseal_policy_pref_from_string

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_POLICY_H */
