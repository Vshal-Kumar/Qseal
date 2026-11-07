/*
 * qseal/src/common.c
 *
 * Mode and role string conversion utilities for QSEAL.
 */

#include "qseal/common.h"
#include <string.h>
#include <strings.h>

const char *qseal_mode_to_string(qseal_mode_t mode) {
    switch (mode) {
        case QSEAL_MODE_CLASSICAL: return "classical";
        case QSEAL_MODE_PQC:       return "pqc";
        case QSEAL_MODE_HYBRID:    return "hybrid";
        case QSEAL_MODE_ADAPTIVE:  return "adaptive";
        default:                        return "unknown";
    }
}

qseal_mode_t qseal_mode_from_string(const char *str) {
    if (!str) return QSEAL_MODE_UNKNOWN;
    if (strcasecmp(str, "classical") == 0) return QSEAL_MODE_CLASSICAL;
    if (strcasecmp(str, "pqc") == 0 || strcasecmp(str, "post-quantum") == 0) return QSEAL_MODE_PQC;
    if (strcasecmp(str, "hybrid") == 0) return QSEAL_MODE_HYBRID;
    if (strcasecmp(str, "adaptive") == 0) return QSEAL_MODE_ADAPTIVE;
    return QSEAL_MODE_UNKNOWN;
}

const char *qseal_role_to_string(qseal_role_t role) {
    switch (role) {
        case QSEAL_ROLE_SERVER: return "server";
        case QSEAL_ROLE_CLIENT: return "client";
        default:                     return "unknown";
    }
}

qseal_role_t qseal_role_from_string(const char *str) {
    if (!str) return QSEAL_ROLE_UNKNOWN;
    if (strcasecmp(str, "server") == 0) return QSEAL_ROLE_SERVER;
    if (strcasecmp(str, "client") == 0) return QSEAL_ROLE_CLIENT;
    return QSEAL_ROLE_UNKNOWN;
}
