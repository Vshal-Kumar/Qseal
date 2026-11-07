/*
 * qseal/include/qseal/common.h
 *
 * Common types, enums, limits, and product constants for QSEAL.
 */

#ifndef QSEAL_COMMON_H
#define QSEAL_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QSEAL_PRODUCT_NAME          "QSEAL"
#define QSEAL_FULL_NAME             "Quantum-Secure Enterprise Access & Link"
#define QSEAL_VERSION_STRING        "1.0.0"
#define QSEAL_DEFAULT_SERVER_CONFIG "/etc/qseal/server.yaml"
#define QSEAL_DEFAULT_CLIENT_CONFIG "/etc/qseal/client.yaml"
#define QSEAL_DEFAULT_CONFIG        "/etc/qseal/qseal.yaml"
#define QSEAL_LEGACY_CONFIG         "/etc/qseal/qseal.json"
#define QSEAL_DEFAULT_VAR_DIR       "/var/lib/qseal"
#define QSEAL_DEFAULT_LOG_DIR       "/var/log/qseal"
#define QSEAL_LOCAL_CONFIG          "config/qseal.yaml"
#define QSEAL_LOCAL_VAR_DIR         "var"
#define QSEAL_LOCAL_LOG_DIR         "logs"

/* Operating Modes */
typedef enum {
    QSEAL_MODE_UNKNOWN   = 0,
    QSEAL_MODE_CLASSICAL = 1,
    QSEAL_MODE_PQC       = 2,
    QSEAL_MODE_HYBRID    = 3,
    QSEAL_MODE_ADAPTIVE  = 4
} qseal_mode_t;

/* Device Roles */
typedef enum {
    QSEAL_ROLE_UNKNOWN = 0,
    QSEAL_ROLE_SERVER  = 1,
    QSEAL_ROLE_CLIENT  = 2
} qseal_role_t;

/* Standard Ports & Defaults */
#define QSEAL_DEFAULT_PORT                9877
#define QSEAL_DEFAULT_BIND_IP             "0.0.0.0"
#define QSEAL_DEFAULT_SERVER_HOST         "127.0.0.1"

#define QSEAL_PORT_CLASSICAL 9877
#define QSEAL_PORT_PQC       9877
#define QSEAL_PORT_HYBRID    9877
#define QSEAL_PORT_ADAPTIVE  9877

#define QSEAL_DEFAULT_PORT_CLASSICAL 9877
#define QSEAL_DEFAULT_PORT_PQC       9877
#define QSEAL_DEFAULT_PORT_HYBRID    9877
#define QSEAL_DEFAULT_PORT_ADAPTIVE  9877

/* Limits */
#define QSEAL_MAX_PATH_LEN       1024
#define QSEAL_MAX_IP_LEN         64
#define QSEAL_MAX_ID_LEN         64
#define QSEAL_MAX_LINE_LEN       2048
#define QSEAL_MAX_SESSIONS       256
#define QSEAL_MAX_PROFILE_NAME   64
#define QSEAL_MAX_BUFFER_SIZE    65536

const char *qseal_mode_to_string(qseal_mode_t mode);
qseal_mode_t qseal_mode_from_string(const char *str);

const char *qseal_role_to_string(qseal_role_t role);
qseal_role_t qseal_role_from_string(const char *str);

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
typedef qseal_mode_t securecomm_mode_t;
#define SECURECOMM_MODE_UNKNOWN   QSEAL_MODE_UNKNOWN
#define SECURECOMM_MODE_CLASSICAL QSEAL_MODE_CLASSICAL
#define SECURECOMM_MODE_PQC       QSEAL_MODE_PQC
#define SECURECOMM_MODE_HYBRID    QSEAL_MODE_HYBRID
#define SECURECOMM_MODE_ADAPTIVE  QSEAL_MODE_ADAPTIVE

typedef qseal_role_t securecomm_role_t;
#define SECURECOMM_ROLE_UNKNOWN QSEAL_ROLE_UNKNOWN
#define SECURECOMM_ROLE_SERVER  QSEAL_ROLE_SERVER
#define SECURECOMM_ROLE_CLIENT  QSEAL_ROLE_CLIENT

#define SECURECOMM_PRODUCT_NAME     QSEAL_PRODUCT_NAME
#define SECURECOMM_VERSION_STRING   QSEAL_VERSION_STRING
#define SECURECOMM_DEFAULT_CONFIG   QSEAL_DEFAULT_CONFIG
#define SECURECOMM_DEFAULT_VAR_DIR  QSEAL_DEFAULT_VAR_DIR
#define SECURECOMM_DEFAULT_LOG_DIR  QSEAL_DEFAULT_LOG_DIR
#define SECURECOMM_DEFAULT_PORT     QSEAL_DEFAULT_PORT
#define SECURECOMM_DEFAULT_SERVER_HOST QSEAL_DEFAULT_SERVER_HOST
#define SECURECOMM_DEFAULT_BIND_IP     QSEAL_DEFAULT_BIND_IP

#define SECURECOMM_MAX_PATH_LEN     QSEAL_MAX_PATH_LEN
#define SECURECOMM_MAX_IP_LEN       QSEAL_MAX_IP_LEN
#define SECURECOMM_MAX_ID_LEN       QSEAL_MAX_ID_LEN
#define SECURECOMM_MAX_LINE_LEN     QSEAL_MAX_LINE_LEN
#define SECURECOMM_MAX_SESSIONS     QSEAL_MAX_SESSIONS
#define SECURECOMM_MAX_PROFILE_NAME QSEAL_MAX_PROFILE_NAME
#define SECURECOMM_MAX_BUFFER_SIZE  QSEAL_MAX_BUFFER_SIZE

#define securecomm_mode_to_string   qseal_mode_to_string
#define securecomm_mode_from_string qseal_mode_from_string
#define securecomm_role_to_string   qseal_role_to_string
#define securecomm_role_from_string qseal_role_from_string

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_COMMON_H */
