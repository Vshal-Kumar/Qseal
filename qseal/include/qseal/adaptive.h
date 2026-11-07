/*
 * qseal/include/qseal/adaptive.h
 *
 * Deterministic and explainable Adaptive Cryptographic Profile Selection Engine.
 * Implements 5-stage pipeline: Capability -> Policy -> Resource -> Peer -> Ranking.
 */

#ifndef QSEAL_ADAPTIVE_H
#define QSEAL_ADAPTIVE_H

#include "common.h"
#include "device_profile.h"
#include "profile_registry.h"
#include "policy.h"
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ADAPTIVE_MAX_CANDIDATES 16

typedef struct {
    const qseal_profile_t *profile;
    char reason[128];
} adaptive_rejected_candidate_t;

typedef struct {
    const qseal_profile_t *selected_profile;
    
    size_t eligible_count;
    const qseal_profile_t *eligible_profiles[ADAPTIVE_MAX_CANDIDATES];
    
    size_t rejected_count;
    adaptive_rejected_candidate_t rejected_candidates[ADAPTIVE_MAX_CANDIDATES];
    
    char decision_summary[512];
    bool policy_violation;
    bool no_compatible_candidate;
} qseal_adaptive_decision_t;

/* Run full 5-stage adaptive selection */
int qseal_adaptive_select(const qseal_device_profile_t *device,
                          const qseal_policy_t *policy,
                          const char *peer_supported_profiles[],
                          size_t peer_supported_count,
                          qseal_adaptive_decision_t *out_decision);

/* Formatted explainability report */
void qseal_adaptive_explain(const qseal_adaptive_decision_t *decision,
                            const qseal_device_profile_t *device,
                            const qseal_policy_t *policy,
                            FILE *out);

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
typedef qseal_adaptive_decision_t securecomm_adaptive_decision_t;
#define securecomm_adaptive_select qseal_adaptive_select
#define securecomm_adaptive_explain qseal_adaptive_explain

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_ADAPTIVE_H */
