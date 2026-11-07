/*
 * qseal/include/qseal/config.h
 *
 * Persistent configuration schema, validation, and serialization for QSEAL.
 * Enforces secret suppression and atomic file updates.
 */

#ifndef QSEAL_CONFIG_H
#define QSEAL_CONFIG_H

#include "common.h"
#include "policy.h"
#include "logging.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char host[QSEAL_MAX_IP_LEN];
    uint16_t port;
    char fingerprint[65];
    uint32_t priority;
    bool enabled;
} qseal_server_entry_t;

typedef struct {
    uint32_t version;                                /* Config schema version (e.g. 1) */
    qseal_role_t role;                               /* SERVER or CLIENT */
    qseal_mode_t mode;                               /* CLASSICAL, PQC, HYBRID, ADAPTIVE */
    char profile_id[QSEAL_MAX_PROFILE_NAME];         /* Target or preferred profile */
    
    /* Network Settings */
    char bind_address[QSEAL_MAX_IP_LEN];             /* Server local listening IP (e.g. "0.0.0.0", "::") */
    char advertised_endpoint[QSEAL_MAX_IP_LEN];      /* Globally reachable public IP/host & port */
    char server_address[QSEAL_MAX_IP_LEN];           /* Remote server IP/host for client */
    char server_host[QSEAL_MAX_IP_LEN];              /* Alias for server_address */
    uint16_t port;                                   /* UDP listening/connect port (default: 9877) */
    uint32_t connect_timeout_ms;                     /* Handshake timeout */
    uint32_t connection_timeout_ms;                  /* Alias for connect_timeout_ms */
    uint32_t reconnect_attempts;                     /* Auto-reconnect count (0=infinite) */
    uint32_t heartbeat_interval_sec;                 /* Heartbeat interval in seconds (default: 15) */
    uint32_t session_timeout_sec;                    /* Inactivity session timeout in seconds (default: 60) */
    
    /* Identity & Trust Settings */
    char device_id[QSEAL_MAX_ID_LEN];                /* Local device identifier */
    char private_key_path[QSEAL_MAX_PATH_LEN];       /* Private key location (0600) */
    char public_key_path[QSEAL_MAX_PATH_LEN];        /* Public key location */
    char trust_store_path[QSEAL_MAX_PATH_LEN];       /* Pinned peer identities */
    char expected_server_id[QSEAL_MAX_ID_LEN];       /* Target server expected identity */
    bool require_client_auth;                        /* Enforce mutual client authentication */
    bool allow_tofu;                                 /* Trust on first use */
    
    /* Multi-Server Scalability (Client) */
    qseal_server_entry_t servers[8];                 /* Multi-server fallback list */
    uint32_t server_count;                           /* Number of configured servers */
    
    /* Network & Routing Capabilities */
    bool allow_client_to_client;                     /* Allow client-to-client relaying/messaging */
    
    /* Resource & Performance Limits */
    uint32_t max_concurrent_sessions;                /* Max concurrent client sessions */
    uint32_t rx_buffer_kb;                           /* Socket receive buffer size */
    uint32_t worker_threads;                         /* Worker thread pool size */
    
    /* Adaptive Policy */
    qseal_policy_t policy;
    
    /* Logging */
    qseal_log_level_t log_level;
    char log_filepath[QSEAL_MAX_PATH_LEN];
    
    /* System Service Options */
    bool auto_start_service;
} qseal_config_t;

/* Initialize configuration with sane, safe defaults */
void qseal_config_init_default(qseal_config_t *cfg);

static inline void qseal_config_init_defaults(qseal_config_t *cfg) {
    qseal_config_init_default(cfg);
}

/* Load from file (auto-detects YAML or JSON) */
int  qseal_config_load(qseal_config_t *cfg, const char *path);
int  qseal_config_load_yaml(qseal_config_t *cfg, const char *path);

/* Save to file atomically (auto-formats YAML or JSON based on file extension) */
int  qseal_config_save(const qseal_config_t *cfg, const char *path);
int  qseal_config_save_yaml(const qseal_config_t *cfg, const char *path);
static inline int qseal_config_save_atomic(const qseal_config_t *cfg, const char *path) {
    return qseal_config_save(cfg, path);
}

/* Validate all settings and enforce security invariants */
int  qseal_config_validate_full(const qseal_config_t *cfg, char *out_err, size_t err_max);
static inline int qseal_config_validate(const qseal_config_t *cfg) {
    return qseal_config_validate_full(cfg, NULL, 0);
}

/* Print configuration to stream, redacting all sensitive paths/keys */
void qseal_config_show(const qseal_config_t *cfg, FILE *out, bool redact_secrets);
static inline void qseal_config_print(const qseal_config_t *cfg, FILE *out) {
    qseal_config_show(cfg, out, true);
}

/* Auto-detect active configuration path */
const char *qseal_config_find_active_path(void);

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
typedef qseal_config_t securecomm_config_t;
#define securecomm_config_init_default  qseal_config_init_default
#define securecomm_config_init_defaults qseal_config_init_defaults
#define securecomm_config_load          qseal_config_load
#define securecomm_config_load_yaml     qseal_config_load_yaml
#define securecomm_config_save          qseal_config_save
#define securecomm_config_save_yaml     qseal_config_save_yaml
#define securecomm_config_save_atomic   qseal_config_save_atomic
#define securecomm_config_validate_full qseal_config_validate_full
#define securecomm_config_validate      qseal_config_validate
#define securecomm_config_show          qseal_config_show
#define securecomm_config_print         qseal_config_print
#define securecomm_config_find_active_path qseal_config_find_active_path

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_CONFIG_H */
