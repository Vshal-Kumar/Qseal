/*
 * securecomm/include/securecomm/common.h
 *
 * Common types, enums, limits, and product constants for SecureComm.
 */

#ifndef SECURECOMM_COMMON_H
#define SECURECOMM_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QSEAL_PRODUCT_NAME          "QSEAL"
#define QSEAL_FULL_NAME             "Quantum-Secure Enterprise Access & Link"
#define QSEAL_VERSION_STRING        "1.0.0"
#define QSEAL_DEFAULT_SERVER_CONFIG "/etc/qseal/server.json"
#define QSEAL_DEFAULT_CLIENT_CONFIG "/etc/qseal/client.json"
#define QSEAL_DEFAULT_CONFIG        "/etc/qseal/qseal.json"
#define QSEAL_DEFAULT_VAR_DIR       "/var/lib/qseal"
#define QSEAL_DEFAULT_LOG_DIR       "/var/log/qseal"

#define SECURECOMM_PRODUCT_NAME     "QSEAL"
#define SECURECOMM_VERSION_STRING   "1.0.0"
#define SECURECOMM_DEFAULT_CONFIG   "/etc/qseal/qseal.json"
#define SECURECOMM_LEGACY_CONFIG    "/etc/securecomm/securecomm.json"
#define SECURECOMM_LOCAL_CONFIG     "config/qseal.json"
#define SECURECOMM_DEFAULT_VAR_DIR  "/var/lib/qseal"
#define SECURECOMM_LOCAL_VAR_DIR    "var"
#define SECURECOMM_DEFAULT_LOG_DIR  "/var/log/qseal"
#define SECURECOMM_LOCAL_LOG_DIR    "logs"

/* Operating Modes */
typedef enum {
    SECURECOMM_MODE_UNKNOWN   = 0,
    SECURECOMM_MODE_CLASSICAL = 1,
    SECURECOMM_MODE_PQC       = 2,
    SECURECOMM_MODE_HYBRID    = 3,
    SECURECOMM_MODE_ADAPTIVE  = 4
} securecomm_mode_t;

typedef securecomm_mode_t qseal_mode_t;
#define QSEAL_MODE_UNKNOWN   SECURECOMM_MODE_UNKNOWN
#define QSEAL_MODE_CLASSICAL SECURECOMM_MODE_CLASSICAL
#define QSEAL_MODE_PQC       SECURECOMM_MODE_PQC
#define QSEAL_MODE_HYBRID    SECURECOMM_MODE_HYBRID
#define QSEAL_MODE_ADAPTIVE  SECURECOMM_MODE_ADAPTIVE

/* Device Roles */
typedef enum {
    SECURECOMM_ROLE_UNKNOWN = 0,
    SECURECOMM_ROLE_SERVER  = 1,
    SECURECOMM_ROLE_CLIENT  = 2
} securecomm_role_t;

typedef securecomm_role_t qseal_role_t;
#define QSEAL_ROLE_UNKNOWN SECURECOMM_ROLE_UNKNOWN
#define QSEAL_ROLE_SERVER  SECURECOMM_ROLE_SERVER
#define QSEAL_ROLE_CLIENT  SECURECOMM_ROLE_CLIENT

/* Standard Ports & Defaults */
#define QSEAL_DEFAULT_PORT                9877
#define QSEAL_DEFAULT_BIND_IP             "0.0.0.0"
#define QSEAL_DEFAULT_SERVER_HOST         "127.0.0.1"

#define SECURECOMM_DEFAULT_PORT           9877
#define SECURECOMM_DEFAULT_SERVER_HOST    "127.0.0.1"
#define SECURECOMM_DEFAULT_BIND_IP        "0.0.0.0"

#define SECURECOMM_PORT_CLASSICAL 9877
#define SECURECOMM_PORT_PQC       9877
#define SECURECOMM_PORT_HYBRID    9877
#define SECURECOMM_PORT_ADAPTIVE  9877

#define SECURECOMM_DEFAULT_PORT_CLASSICAL 9877
#define SECURECOMM_DEFAULT_PORT_PQC       9877
#define SECURECOMM_DEFAULT_PORT_HYBRID    9877
#define SECURECOMM_DEFAULT_PORT_ADAPTIVE  9877

/* Limits */
#define SECURECOMM_MAX_PATH_LEN       1024
#define SECURECOMM_MAX_IP_LEN         64
#define SECURECOMM_MAX_ID_LEN         64
#define SECURECOMM_MAX_LINE_LEN       2048
#define SECURECOMM_MAX_SESSIONS       256
#define SECURECOMM_MAX_PROFILE_NAME   64
#define SECURECOMM_MAX_BUFFER_SIZE    65536

const char *securecomm_mode_to_string(securecomm_mode_t mode);
securecomm_mode_t securecomm_mode_from_string(const char *str);

const char *securecomm_role_to_string(securecomm_role_t role);
securecomm_role_t securecomm_role_from_string(const char *str);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_COMMON_H */
