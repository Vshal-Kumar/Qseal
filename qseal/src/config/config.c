/*
 * qseal/src/config/config.c
 *
 * Configuration loader, validator, serializer, and atomic writer.
 */

#define _POSIX_C_SOURCE 200809L
#include "qseal/config.h"
#include "qseal/error.h"
#include "json_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static void ensure_dir_exists(const char *dir) {
    if (!dir || strlen(dir) == 0) return;
    char tmp[QSEAL_MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp);
    for (size_t i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            mkdir(tmp, 0755);
            tmp[i] = '/';
        }
    }
    mkdir(tmp, 0755);
}

void qseal_config_init_default(qseal_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    
    cfg->version = 1;
    cfg->role = QSEAL_ROLE_SERVER;
    cfg->mode = QSEAL_MODE_HYBRID;
    strncpy(cfg->profile_id, "profile-hybrid-1", sizeof(cfg->profile_id) - 1);
    
    strncpy(cfg->bind_address, "0.0.0.0", sizeof(cfg->bind_address) - 1);
    strncpy(cfg->advertised_endpoint, "", sizeof(cfg->advertised_endpoint) - 1);
    strncpy(cfg->server_address, "127.0.0.1", sizeof(cfg->server_address) - 1);
    strncpy(cfg->server_host, "127.0.0.1", sizeof(cfg->server_host) - 1);
    cfg->port = 9877;
    cfg->connect_timeout_ms = 5000;
    cfg->connection_timeout_ms = 5000;
    cfg->reconnect_attempts = 5;
    cfg->heartbeat_interval_sec = 15;
    cfg->session_timeout_sec = 60;
    cfg->allow_client_to_client = true;
    cfg->server_count = 0;
    
    strncpy(cfg->device_id, "qseal-node", sizeof(cfg->device_id) - 1);
    if (access("/etc/qseal", W_OK) == 0 || getuid() == 0) {
        strncpy(cfg->private_key_path, "/etc/qseal/identity.key", sizeof(cfg->private_key_path) - 1);
        strncpy(cfg->public_key_path, "/etc/qseal/identity.pub", sizeof(cfg->public_key_path) - 1);
        strncpy(cfg->trust_store_path, "/etc/qseal/trust_store.txt", sizeof(cfg->trust_store_path) - 1);
    } else {
        const char *home = getenv("HOME");
        if (home && strlen(home) > 0) {
            snprintf(cfg->private_key_path, sizeof(cfg->private_key_path), "%s/.config/qseal/identity.key", home);
            snprintf(cfg->public_key_path, sizeof(cfg->public_key_path), "%s/.config/qseal/identity.pub", home);
            snprintf(cfg->trust_store_path, sizeof(cfg->trust_store_path), "%s/.config/qseal/trust_store.txt", home);
        } else {
            strncpy(cfg->private_key_path, "/tmp/qseal_identity.key", sizeof(cfg->private_key_path) - 1);
            strncpy(cfg->public_key_path, "/tmp/qseal_identity.pub", sizeof(cfg->public_key_path) - 1);
            strncpy(cfg->trust_store_path, "/tmp/qseal_trust_store.txt", sizeof(cfg->trust_store_path) - 1);
        }
    }
    cfg->require_client_auth = true;
    
    cfg->max_concurrent_sessions = 64;
    cfg->rx_buffer_kb = 256;
    cfg->worker_threads = 4;
    
    qseal_policy_init_default(&cfg->policy);
    cfg->allow_tofu = true;
    cfg->policy.allow_tofu = true;
    
    cfg->log_level = QSEAL_LOG_INFO;
    strncpy(cfg->log_filepath, "", sizeof(cfg->log_filepath) - 1);
    cfg->auto_start_service = false;
}

#include <ctype.h>
#include <strings.h>

static char *trim_whitespace(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static void strip_quotes(char *str) {
    size_t len = strlen(str);
    if (len >= 2 && ((str[0] == '"' && str[len - 1] == '"') || (str[0] == '\'' && str[len - 1] == '\''))) {
        str[len - 1] = '\0';
        memmove(str, str + 1, len - 1);
    }
}

static int parse_yaml_buffer(qseal_config_t *cfg, const char *buf) {
    if (!cfg || !buf) return -1;
    char line[1024];
    char section[64] = "";
    const char *p = buf;

    while (*p) {
        size_t i = 0;
        while (*p && *p != '\n' && i < sizeof(line) - 1) {
            line[i++] = *p++;
        }
        if (*p == '\n') p++;
        line[i] = '\0';

        char *trimmed = trim_whitespace(line);
        if (*trimmed == '\0' || *trimmed == '#') continue;

        size_t tlen = strlen(trimmed);
        if (tlen > 1 && trimmed[tlen - 1] == ':') {
            trimmed[tlen - 1] = '\0';
            char *sec_name = trim_whitespace(trimmed);
            strncpy(section, sec_name, sizeof(section) - 1);
            if (strcasecmp(section, "server") == 0) {
                cfg->role = QSEAL_ROLE_SERVER;
            } else if (strcasecmp(section, "client") == 0) {
                cfg->role = QSEAL_ROLE_CLIENT;
            }
            continue;
        }

        char *colon = strchr(trimmed, ':');
        if (!colon) continue;
        *colon = '\0';
        char *key = trim_whitespace(trimmed);
        char *val = trim_whitespace(colon + 1);

        if (val[0] != '"' && val[0] != '\'') {
            char *hash = strchr(val, '#');
            if (hash) {
                *hash = '\0';
                val = trim_whitespace(val);
            }
        }
        strip_quotes(val);

        if (strcasecmp(key, "id") == 0 || strcasecmp(key, "device_id") == 0) {
            strncpy(cfg->device_id, val, sizeof(cfg->device_id) - 1);
        } else if (strcasecmp(key, "bind_address") == 0) {
            strncpy(cfg->bind_address, val, sizeof(cfg->bind_address) - 1);
        } else if (strcasecmp(key, "advertised_public_ipv4") == 0 || strcasecmp(key, "advertised_endpoint") == 0) {
            strncpy(cfg->advertised_endpoint, val, sizeof(cfg->advertised_endpoint) - 1);
        } else if (strcasecmp(key, "public_ipv4") == 0 || strcasecmp(key, "public_ipv6") == 0 ||
                   strcasecmp(key, "server_address") == 0 || strcasecmp(key, "server_host") == 0 ||
                   (strcasecmp(key, "hostname") == 0 && strlen(val) > 0)) {
            strncpy(cfg->server_host, val, sizeof(cfg->server_host) - 1);
            strncpy(cfg->server_address, val, sizeof(cfg->server_address) - 1);
        } else if (strcasecmp(key, "port") == 0) {
            cfg->port = (uint16_t)atoi(val);
        } else if (strcasecmp(key, "preferred_profile") == 0 || strcasecmp(key, "mode") == 0) {
            cfg->mode = qseal_mode_from_string(val);
        } else if (strcasecmp(key, "allowed_profiles") == 0 || strcasecmp(key, "profile_id") == 0) {
            strncpy(cfg->profile_id, val, sizeof(cfg->profile_id) - 1);
        } else if (strcasecmp(key, "identity_path") == 0 || strcasecmp(key, "private_key_path") == 0 || strcasecmp(key, "key_path") == 0) {
            strncpy(cfg->private_key_path, val, sizeof(cfg->private_key_path) - 1);
        } else if (strcasecmp(key, "public_key_path") == 0) {
            strncpy(cfg->public_key_path, val, sizeof(cfg->public_key_path) - 1);
        } else if (strcasecmp(key, "trust_store_path") == 0) {
            strncpy(cfg->trust_store_path, val, sizeof(cfg->trust_store_path) - 1);
        } else if (strcasecmp(key, "expected_server_identity") == 0 || strcasecmp(key, "expected_server_id") == 0) {
            strncpy(cfg->expected_server_id, val, sizeof(cfg->expected_server_id) - 1);
        } else if (strcasecmp(key, "require_client_auth") == 0) {
            cfg->require_client_auth = (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "yes") == 0);
        } else if (strcasecmp(key, "allow_tofu") == 0) {
            cfg->allow_tofu = cfg->policy.allow_tofu = (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "yes") == 0);
        } else if (strcasecmp(key, "require_quantum_resistance") == 0) {
            cfg->policy.require_quantum_resistance = (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "yes") == 0);
        } else if (strcasecmp(key, "max_clients") == 0 || strcasecmp(key, "max_concurrent_sessions") == 0) {
            cfg->max_concurrent_sessions = (uint32_t)atoi(val);
        } else if (strcasecmp(key, "heartbeat_interval_sec") == 0) {
            cfg->heartbeat_interval_sec = (uint32_t)atoi(val);
        } else if (strcasecmp(key, "inactive_session_timeout_sec") == 0 || strcasecmp(key, "session_expiration_sec") == 0 || strcasecmp(key, "session_timeout_sec") == 0) {
            cfg->session_timeout_sec = (uint32_t)atoi(val);
        } else if (strcasecmp(key, "handshake_timeout_ms") == 0 || strcasecmp(key, "connect_timeout_ms") == 0) {
            cfg->connect_timeout_ms = (uint32_t)atoi(val);
        } else if (strcasecmp(key, "connection_timeout_ms") == 0) {
            cfg->connection_timeout_ms = (uint32_t)atoi(val);
        } else if (strcasecmp(key, "reconnect_attempts") == 0) {
            cfg->reconnect_attempts = (uint32_t)atoi(val);
        } else if (strcasecmp(key, "allow_client_to_client") == 0) {
            cfg->allow_client_to_client = (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "yes") == 0);
        } else if (strcasecmp(key, "auto_connect") == 0) {
            cfg->auto_start_service = (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "yes") == 0);
        } else if (strcasecmp(key, "level") == 0) {
            cfg->log_level = qseal_log_level_from_string(val);
        } else if (strcasecmp(key, "file") == 0 || strcasecmp(key, "log_filepath") == 0) {
            strncpy(cfg->log_filepath, val, sizeof(cfg->log_filepath) - 1);
        }
    }
    return 0;
}

static char *generate_yaml_string(const qseal_config_t *cfg) {
    char *buf = (char *)malloc(8192);
    if (!buf) return NULL;

    if (cfg->role == QSEAL_ROLE_SERVER) {
        snprintf(buf, 8192,
            "# QSEAL Server Configuration\n"
            "# Production Quantum-Secure Networking Platform\n\n"
            "server:\n"
            "  id: \"%s\"\n"
            "  name: \"QSEAL Server Node\"\n"
            "  identity_path: \"%s\"\n\n"
            "network:\n"
            "  bind_address: \"%s\"\n"
            "  advertised_public_ipv4: \"%s\"\n"
            "  advertised_public_ipv6: \"\"\n"
            "  port: %u\n"
            "  transport: \"udp\"\n"
            "  hostname: \"\"\n\n"
            "security:\n"
            "  allowed_profiles: \"hybrid,pqc\"\n"
            "  preferred_profile: \"%s\"\n"
            "  require_client_auth: %s\n"
            "  allow_tofu: %s\n"
            "  key_path: \"%s\"\n"
            "  public_key_path: \"%s\"\n"
            "  trust_store_path: \"%s\"\n"
            "  session_expiration_sec: %u\n"
            "  rekey_interval_sec: 1800\n\n"
            "connections:\n"
            "  max_clients: %u\n"
            "  handshake_timeout_ms: %u\n"
            "  connection_timeout_ms: %u\n"
            "  heartbeat_interval_sec: %u\n"
            "  inactive_session_timeout_sec: %u\n"
            "  allow_client_to_client: %s\n\n"
            "client_access:\n"
            "  enrollment_policy: \"%s\"\n"
            "  allowed_clients: \"*\"\n\n"
            "logging:\n"
            "  level: \"%s\"\n"
            "  file: \"%s\"\n"
            "  retention_days: 7\n",
            cfg->device_id,
            cfg->private_key_path,
            cfg->bind_address,
            cfg->advertised_endpoint,
            cfg->port,
            qseal_mode_to_string(cfg->mode),
            cfg->require_client_auth ? "true" : "false",
            cfg->allow_tofu ? "true" : "false",
            cfg->private_key_path,
            cfg->public_key_path,
            cfg->trust_store_path,
            cfg->session_timeout_sec,
            cfg->max_concurrent_sessions,
            cfg->connect_timeout_ms,
            cfg->connection_timeout_ms,
            cfg->heartbeat_interval_sec,
            cfg->session_timeout_sec,
            cfg->allow_client_to_client ? "true" : "false",
            cfg->allow_tofu ? "tofu" : "strict",
            qseal_log_level_to_string(cfg->log_level),
            cfg->log_filepath);
    } else {
        const char *srv = strlen(cfg->server_address) > 0 ? cfg->server_address : cfg->server_host;
        snprintf(buf, 8192,
            "# QSEAL Client Configuration\n"
            "# Production Quantum-Secure Networking Platform\n\n"
            "client:\n"
            "  id: \"%s\"\n"
            "  name: \"QSEAL Client Node\"\n"
            "  identity_path: \"%s\"\n\n"
            "server:\n"
            "  public_ipv4: \"%s\"\n"
            "  public_ipv6: \"\"\n"
            "  hostname: \"\"\n"
            "  port: %u\n"
            "  transport: \"udp\"\n"
            "  expected_server_identity: \"%s\"\n\n"
            "security:\n"
            "  allowed_profiles: \"hybrid,pqc\"\n"
            "  preferred_profile: \"%s\"\n"
            "  require_quantum_resistance: %s\n"
            "  allow_tofu: %s\n"
            "  key_path: \"%s\"\n"
            "  public_key_path: \"%s\"\n"
            "  trust_store_path: \"%s\"\n\n"
            "connection:\n"
            "  auto_connect: %s\n"
            "  timeout_ms: %u\n"
            "  retry_interval_sec: 5\n"
            "  reconnect_attempts: %u\n"
            "  heartbeat_interval_sec: %u\n"
            "  reconnection_policy: \"exponential_backoff\"\n\n"
            "logging:\n"
            "  level: \"%s\"\n"
            "  file: \"%s\"\n"
            "  retention_days: 7\n",
            cfg->device_id,
            cfg->private_key_path,
            srv,
            cfg->port,
            cfg->expected_server_id,
            qseal_mode_to_string(cfg->mode),
            cfg->policy.require_quantum_resistance ? "true" : "false",
            cfg->allow_tofu ? "true" : "false",
            cfg->private_key_path,
            cfg->public_key_path,
            cfg->trust_store_path,
            cfg->auto_start_service ? "true" : "false",
            cfg->connect_timeout_ms,
            cfg->reconnect_attempts,
            cfg->heartbeat_interval_sec,
            qseal_log_level_to_string(cfg->log_level),
            cfg->log_filepath);
    }
    return buf;
}

const char *qseal_config_find_active_path(void) {
    if (access("/etc/qseal/server.yaml", R_OK) == 0) return "/etc/qseal/server.yaml";
    if (access("/etc/qseal/client.yaml", R_OK) == 0) return "/etc/qseal/client.yaml";
    if (access("/etc/qseal/server.json", R_OK) == 0) return "/etc/qseal/server.json";
    if (access("/etc/qseal/client.json", R_OK) == 0) return "/etc/qseal/client.json";
    if (access("/etc/qseal/qseal.yaml", R_OK) == 0) return "/etc/qseal/qseal.yaml";
    if (access("/etc/qseal/qseal.json", R_OK) == 0) return "/etc/qseal/qseal.json";
    
    const char *home = getenv("HOME");
    if (home) {
        static char user_cfg[QSEAL_MAX_PATH_LEN];
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/server.yaml", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/client.yaml", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/server.json", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/client.json", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/qseal.yaml", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/qseal.json", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
    }
    
    if (access("config/server.yaml", R_OK) == 0) return "config/server.yaml";
    if (access("config/client.yaml", R_OK) == 0) return "config/client.yaml";
    if (access("config/qseal.yaml", R_OK) == 0) return "config/qseal.yaml";
    if (access("config/server.json", R_OK) == 0) return "config/server.json";
    if (access("config/client.json", R_OK) == 0) return "config/client.json";
    if (access("config/qseal.json", R_OK) == 0) return "config/qseal.json";
    if (access(QSEAL_LEGACY_CONFIG, R_OK) == 0) return QSEAL_LEGACY_CONFIG;
    if (access(QSEAL_LOCAL_CONFIG, R_OK) == 0) return QSEAL_LOCAL_CONFIG;
    
    return "/etc/qseal/server.yaml";
}

int qseal_config_load(qseal_config_t *cfg, const char *path) {
    if (!cfg) return QSEAL_ERR_INVALID_ARG;
    if (!path) path = qseal_config_find_active_path();
    
    FILE *f = fopen(path, "rb");
    if (!f) {
        return QSEAL_ERR_CONFIG_NOT_FOUND;
    }
    
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (sz <= 0 || sz > 512 * 1024) { /* 512KB sanity max */
        fclose(f);
        return QSEAL_ERR_CONFIG_PARSE;
    }
    
    char *buf = (char *)malloc(sz + 1);
    if (!buf) {
        fclose(f);
        return QSEAL_ERR_NOMEM;
    }
    
    size_t read_bytes = fread(buf, 1, sz, f);
    fclose(f);
    buf[read_bytes] = '\0';
    
    qseal_config_init_default(cfg);

    /* Check if buffer starts with '{' (JSON) or text/comments (YAML) */
    const char *start = buf;
    while (*start && isspace((unsigned char)*start)) start++;

    if (*start != '{') {
        int y_rc = parse_yaml_buffer(cfg, buf);
        free(buf);
        return (y_rc == 0) ? QSEAL_SUCCESS : QSEAL_ERR_CONFIG_PARSE;
    }

    /* JSON Parser */
    char err[128] = "";
    json_value_t *root = json_parse(buf, err, sizeof(err));
    free(buf);
    
    if (!root || root->type != JSON_OBJECT) {
        json_free(root);
        return QSEAL_ERR_CONFIG_PARSE;
    }
    
    qseal_config_init_default(cfg);
    
    cfg->version = (uint32_t)json_get_int(json_object_get(root, "version"), 1);
    cfg->role = qseal_role_from_string(json_get_string(json_object_get(root, "role"), "server"));
    cfg->mode = qseal_mode_from_string(json_get_string(json_object_get(root, "mode"), "adaptive"));
    
    const char *prof = json_get_string(json_object_get(root, "profile_id"), NULL);
    if (prof) strncpy(cfg->profile_id, prof, sizeof(cfg->profile_id) - 1);
    
    /* Network */
    json_value_t *net = json_object_get(root, "network");
    if (net) {
        const char *bind_ip = json_get_string(json_object_get(net, "bind_address"), NULL);
        if (bind_ip) strncpy(cfg->bind_address, bind_ip, sizeof(cfg->bind_address) - 1);
        
        const char *adv = json_get_string(json_object_get(net, "advertised_endpoint"), NULL);
        if (adv) strncpy(cfg->advertised_endpoint, adv, sizeof(cfg->advertised_endpoint) - 1);

        const char *srv_ip = json_get_string(json_object_get(net, "server_address"), NULL);
        if (!srv_ip) srv_ip = json_get_string(json_object_get(net, "server_host"), NULL);
        if (srv_ip) {
            strncpy(cfg->server_address, srv_ip, sizeof(cfg->server_address) - 1);
            strncpy(cfg->server_host, srv_ip, sizeof(cfg->server_host) - 1);
        }
        
        cfg->port = (uint16_t)json_get_int(json_object_get(net, "port"), cfg->port);
        cfg->connect_timeout_ms = (uint32_t)json_get_int(json_object_get(net, "connect_timeout_ms"), 5000);
        cfg->connection_timeout_ms = cfg->connect_timeout_ms;
        cfg->reconnect_attempts = (uint32_t)json_get_int(json_object_get(net, "reconnect_attempts"), 5);
        cfg->heartbeat_interval_sec = (uint32_t)json_get_int(json_object_get(net, "heartbeat_interval_sec"), 15);
        cfg->session_timeout_sec = (uint32_t)json_get_int(json_object_get(net, "session_timeout_sec"), 60);
        cfg->allow_client_to_client = json_get_bool(json_object_get(net, "allow_client_to_client"), true);
    }
    
    /* Identity */
    json_value_t *id = json_object_get(root, "identity");
    if (id) {
        const char *dev = json_get_string(json_object_get(id, "device_id"), NULL);
        if (dev) strncpy(cfg->device_id, dev, sizeof(cfg->device_id) - 1);
        
        const char *priv = json_get_string(json_object_get(id, "private_key_path"), NULL);
        if (priv) strncpy(cfg->private_key_path, priv, sizeof(cfg->private_key_path) - 1);
        
        const char *pub = json_get_string(json_object_get(id, "public_key_path"), NULL);
        if (pub) strncpy(cfg->public_key_path, pub, sizeof(cfg->public_key_path) - 1);
        
        const char *trust = json_get_string(json_object_get(id, "trust_store_path"), NULL);
        if (trust) strncpy(cfg->trust_store_path, trust, sizeof(cfg->trust_store_path) - 1);
        
        cfg->require_client_auth = json_get_bool(json_object_get(id, "require_client_auth"), true);
    }
    
    /* Policy */
    json_value_t *pol = json_object_get(root, "policy");
    if (pol) {
        cfg->policy.require_quantum_resistance = json_get_bool(json_object_get(pol, "require_quantum_resistance"), true);
        cfg->policy.require_quantum_auth = json_get_bool(json_object_get(pol, "require_quantum_auth"), false);
        cfg->policy.require_dual_combiner = json_get_bool(json_object_get(pol, "require_dual_combiner"), false);
        cfg->policy.allow_classical_fallback = json_get_bool(json_object_get(pol, "allow_classical_fallback"), false);
        cfg->policy.require_fips_algorithms = json_get_bool(json_object_get(pol, "require_fips_algorithms"), true);
        cfg->policy.max_acceptable_latency_ms = (uint32_t)json_get_int(json_object_get(pol, "max_acceptable_latency_ms"), 500);
        cfg->policy.max_memory_budget_mb = (uint32_t)json_get_int(json_object_get(pol, "max_memory_budget_mb"), 256);
        cfg->policy.allow_tofu = json_get_bool(json_object_get(pol, "allow_tofu"), true);
        cfg->allow_tofu = cfg->policy.allow_tofu;
        cfg->policy.preference = qseal_policy_pref_from_string(json_get_string(json_object_get(pol, "preference"), "balanced"));
        cfg->policy.pref = cfg->policy.preference;
    }
    
    /* Resources */
    json_value_t *res = json_object_get(root, "resources");
    if (res) {
        cfg->max_concurrent_sessions = (uint32_t)json_get_int(json_object_get(res, "max_concurrent_sessions"), 64);
        cfg->rx_buffer_kb = (uint32_t)json_get_int(json_object_get(res, "rx_buffer_kb"), 256);
        cfg->worker_threads = (uint32_t)json_get_int(json_object_get(res, "worker_threads"), 4);
    }
    
    /* Logging */
    json_value_t *log = json_object_get(root, "logging");
    if (log) {
        cfg->log_level = qseal_log_level_from_string(json_get_string(json_object_get(log, "level"), "info"));
        const char *lp = json_get_string(json_object_get(log, "file"), "");
        if (lp) strncpy(cfg->log_filepath, lp, sizeof(cfg->log_filepath) - 1);
    }
    
    cfg->auto_start_service = json_get_bool(json_object_get(root, "auto_start_service"), false);
    
    json_free(root);
    return QSEAL_SUCCESS;
}

int qseal_config_save(const qseal_config_t *cfg, const char *path) {
    if (!cfg || !path) return QSEAL_ERR_INVALID_ARG;

    bool is_yaml = false;
    size_t plen = strlen(path);
    if ((plen >= 5 && strcasecmp(path + plen - 5, ".yaml") == 0) ||
        (plen >= 4 && strcasecmp(path + plen - 4, ".yml") == 0)) {
        is_yaml = true;
    }

    char *out_text = NULL;
    if (is_yaml) {
        out_text = generate_yaml_string(cfg);
        if (!out_text) return QSEAL_ERR_NOMEM;
    } else {
        json_value_t *root = json_create_object();
        if (!root) return QSEAL_ERR_NOMEM;
        
        json_object_set(root, "version", json_create_number(cfg->version));
        json_object_set(root, "role", json_create_string(qseal_role_to_string(cfg->role)));
        json_object_set(root, "mode", json_create_string(qseal_mode_to_string(cfg->mode)));
        json_object_set(root, "profile_id", json_create_string(cfg->profile_id));
        
        json_value_t *net = json_create_object();
        const char *srv = strlen(cfg->server_address) > 0 ? cfg->server_address : cfg->server_host;
        json_object_set(net, "bind_address", json_create_string(cfg->bind_address));
        json_object_set(net, "advertised_endpoint", json_create_string(cfg->advertised_endpoint));
        json_object_set(net, "server_address", json_create_string(srv));
        json_object_set(net, "server_host", json_create_string(srv));
        json_object_set(net, "port", json_create_number(cfg->port));
        json_object_set(net, "connect_timeout_ms", json_create_number(cfg->connect_timeout_ms));
        json_object_set(net, "reconnect_attempts", json_create_number(cfg->reconnect_attempts));
        json_object_set(net, "heartbeat_interval_sec", json_create_number(cfg->heartbeat_interval_sec));
        json_object_set(net, "session_timeout_sec", json_create_number(cfg->session_timeout_sec));
        json_object_set(net, "allow_client_to_client", json_create_bool(cfg->allow_client_to_client));
        json_object_set(root, "network", net);
        
        json_value_t *id = json_create_object();
        json_object_set(id, "device_id", json_create_string(cfg->device_id));
        json_object_set(id, "private_key_path", json_create_string(cfg->private_key_path));
        json_object_set(id, "public_key_path", json_create_string(cfg->public_key_path));
        json_object_set(id, "trust_store_path", json_create_string(cfg->trust_store_path));
        json_object_set(id, "require_client_auth", json_create_bool(cfg->require_client_auth));
        json_object_set(root, "identity", id);
        
        json_value_t *pol = json_create_object();
        json_object_set(pol, "require_quantum_resistance", json_create_bool(cfg->policy.require_quantum_resistance));
        json_object_set(pol, "require_quantum_auth", json_create_bool(cfg->policy.require_quantum_auth));
        json_object_set(pol, "require_dual_combiner", json_create_bool(cfg->policy.require_dual_combiner));
        json_object_set(pol, "allow_classical_fallback", json_create_bool(cfg->policy.allow_classical_fallback));
        json_object_set(pol, "require_fips_algorithms", json_create_bool(cfg->policy.require_fips_algorithms));
        json_object_set(pol, "max_acceptable_latency_ms", json_create_number(cfg->policy.max_acceptable_latency_ms));
        json_object_set(pol, "max_memory_budget_mb", json_create_number(cfg->policy.max_memory_budget_mb));
        qseal_policy_pref_t p_pref = cfg->policy.pref ? cfg->policy.pref : cfg->policy.preference;
        json_object_set(pol, "preference", json_create_string(qseal_policy_pref_to_string(p_pref)));
        json_object_set(root, "policy", pol);
        
        json_value_t *res = json_create_object();
        json_object_set(res, "max_concurrent_sessions", json_create_number(cfg->max_concurrent_sessions));
        json_object_set(res, "rx_buffer_kb", json_create_number(cfg->rx_buffer_kb));
        json_object_set(res, "worker_threads", json_create_number(cfg->worker_threads));
        json_object_set(root, "resources", res);
        
        json_value_t *log = json_create_object();
        json_object_set(log, "level", json_create_string(qseal_log_level_to_string(cfg->log_level)));
        json_object_set(log, "file", json_create_string(cfg->log_filepath));
        json_object_set(root, "logging", log);
        
        json_object_set(root, "auto_start_service", json_create_bool(cfg->auto_start_service));
        
        out_text = json_stringify(root, true);
        json_free(root);
        if (!out_text) return QSEAL_ERR_NOMEM;
    }
    
    /* Ensure parent directory of path exists */
    char dir_buf[QSEAL_MAX_PATH_LEN];
    snprintf(dir_buf, sizeof(dir_buf), "%s", path);
    char *last_slash = strrchr(dir_buf, '/');
    if (last_slash) {
        *last_slash = '\0';
        ensure_dir_exists(dir_buf);
    }

    char final_path[QSEAL_MAX_PATH_LEN];
    snprintf(final_path, sizeof(final_path), "%s", path);

    /* Atomic write via temporary file */
    char tmp_path[QSEAL_MAX_PATH_LEN + 16];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", final_path, (int)getpid());
    
    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        const char *home = getenv("HOME");
        if (home && strlen(home) > 0) {
            snprintf(dir_buf, sizeof(dir_buf), "%.900s/.config/qseal", home);
            ensure_dir_exists(dir_buf);
            snprintf(final_path, sizeof(final_path), "%.900s/%s", dir_buf, is_yaml ? "server.yaml" : "qseal.json");
            snprintf(tmp_path, sizeof(tmp_path), "%.950s.tmp.%d", final_path, (int)getpid());
            f = fopen(tmp_path, "wb");
        }
    }
    if (!f) {
        free(out_text);
        return QSEAL_ERR_CONFIG_WRITE;
    }
    
    size_t len = strlen(out_text);
    if (fwrite(out_text, 1, len, f) != len) {
        fclose(f);
        unlink(tmp_path);
        free(out_text);
        return QSEAL_ERR_CONFIG_WRITE;
    }
    
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    free(out_text);
    
    /* Set reasonable permissions: 0600 for config */
    chmod(tmp_path, 0600);
    
    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        return QSEAL_ERR_CONFIG_WRITE;
    }
    
    return QSEAL_SUCCESS;
}

int qseal_config_save_yaml(const qseal_config_t *cfg, const char *path) {
    if (!cfg || !path) return QSEAL_ERR_INVALID_ARG;
    char yaml_path[QSEAL_MAX_PATH_LEN];
    snprintf(yaml_path, sizeof(yaml_path), "%s", path);
    size_t len = strlen(yaml_path);
    if (len < 5 || (strcasecmp(yaml_path + len - 5, ".yaml") != 0 && strcasecmp(yaml_path + len - 4, ".yml") != 0)) {
        snprintf(yaml_path + len, sizeof(yaml_path) - len, ".yaml");
    }
    return qseal_config_save(cfg, yaml_path);
}

int qseal_config_load_yaml(qseal_config_t *cfg, const char *path) {
    return qseal_config_load(cfg, path);
}

int qseal_config_validate_full(const qseal_config_t *cfg, char *out_err, size_t err_max) {
    if (!cfg) {
        if (out_err && err_max) snprintf(out_err, err_max, "Null configuration pointer");
        return QSEAL_ERR_INVALID_ARG;
    }
    if (cfg->role != QSEAL_ROLE_SERVER && cfg->role != QSEAL_ROLE_CLIENT) {
        if (out_err && err_max) snprintf(out_err, err_max, "Invalid role (must be 'server' or 'client')");
        return QSEAL_ERR_CONFIG_VALIDATE;
    }
    if (cfg->mode < QSEAL_MODE_CLASSICAL || cfg->mode > QSEAL_MODE_ADAPTIVE) {
        if (out_err && err_max) snprintf(out_err, err_max, "Invalid mode (must be classical, pqc, hybrid, or adaptive)");
        return QSEAL_ERR_CONFIG_VALIDATE;
    }
    if (cfg->port == 0) {
        if (out_err && err_max) snprintf(out_err, err_max, "Port cannot be 0");
        return QSEAL_ERR_CONFIG_VALIDATE;
    }
    if (cfg->role == QSEAL_ROLE_CLIENT && strlen(cfg->server_address) == 0) {
        if (out_err && err_max) snprintf(out_err, err_max, "Client requires non-empty server_address");
        return QSEAL_ERR_CONFIG_VALIDATE;
    }
    if (strlen(cfg->device_id) == 0) {
        if (out_err && err_max) snprintf(out_err, err_max, "Device identifier cannot be empty");
        return QSEAL_ERR_CONFIG_VALIDATE;
    }
    
    /* Downstream policy check: if PQC or Hybrid is chosen, fallback must not be secretly forced */
    if ((cfg->mode == QSEAL_MODE_PQC || cfg->mode == QSEAL_MODE_HYBRID) &&
        cfg->policy.allow_classical_fallback) {
        /* Allowed only if explicitly permitted, warn or validate */
    }
    
    return QSEAL_SUCCESS;
}

void qseal_config_show(const qseal_config_t *cfg, FILE *out, bool redact_secrets) {
    if (!cfg || !out) return;
    
    fprintf(out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    fprintf(out, "  QSEAL Quantum-Secure Networking Configuration Summary\n");
    fprintf(out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    fprintf(out, "  • Schema Version   : %u\n", cfg->version);
    fprintf(out, "  • Device Role      : %s\n", qseal_role_to_string(cfg->role));
    fprintf(out, "  • Operating Mode   : %s\n", qseal_mode_to_string(cfg->mode));
    fprintf(out, "  • Target Profile   : %s\n", cfg->profile_id);
    fprintf(out, "  • Device Identifier: %s\n", cfg->device_id);
    
    if (cfg->role == QSEAL_ROLE_SERVER) {
        fprintf(out, "  • Local Bind IP    : %s:%u\n", cfg->bind_address, cfg->port);
        fprintf(out, "  • Advertised Pub EP: %s\n", strlen(cfg->advertised_endpoint) ? cfg->advertised_endpoint : "(Using Direct Local Interface IP)");
        fprintf(out, "  • Max Sessions     : %u\n", cfg->max_concurrent_sessions);
        fprintf(out, "  • Client Routing   : %s\n", cfg->allow_client_to_client ? "ENABLED (Peer-to-Peer messaging)" : "DISABLED (Isolated)");
    } else {
        fprintf(out, "  • Server Target    : %s:%u\n", cfg->server_address, cfg->port);
        fprintf(out, "  • Timeout / Retry  : %u ms / %u attempts\n", cfg->connect_timeout_ms, cfg->reconnect_attempts);
        fprintf(out, "  • Heartbeat Every  : %u seconds\n", cfg->heartbeat_interval_sec);
    }
    
    fprintf(out, "\n  [Identity & Cryptography]\n");
    if (redact_secrets) {
        fprintf(out, "  • Private Key Path : [REDACTED FOR SECURITY]\n");
    } else {
        fprintf(out, "  • Private Key Path : %s (0600)\n", cfg->private_key_path);
    }
    fprintf(out, "  • Public Key Path  : %s\n", cfg->public_key_path);
    fprintf(out, "  • Trust Store Path : %s\n", cfg->trust_store_path);
    fprintf(out, "  • Client Auth Req  : %s\n", cfg->require_client_auth ? "YES (Mutual Authentication)" : "NO");
    
    fprintf(out, "\n  [Adaptive Security Policy]\n");
    fprintf(out, "  • Require Quantum  : %s\n", cfg->policy.require_quantum_resistance ? "YES" : "NO");
    fprintf(out, "  • Require QuantumAuth: %s\n", cfg->policy.require_quantum_auth ? "YES" : "NO");
    fprintf(out, "  • Require Hybrid   : %s\n", cfg->policy.require_dual_combiner ? "YES" : "NO");
    fprintf(out, "  • Classical Fallback: %s\n", cfg->policy.allow_classical_fallback ? "PERMITTED" : "STRICTLY PROHIBITED");
    fprintf(out, "  • Optimization Goal: %s\n", qseal_policy_pref_to_string(cfg->policy.preference));
    
    fprintf(out, "\n  [System & Logging]\n");
    fprintf(out, "  • Log Level        : %s\n", qseal_log_level_to_string(cfg->log_level));
    fprintf(out, "  • Log File         : %s\n", strlen(cfg->log_filepath) ? cfg->log_filepath : "<standard output>");
    fprintf(out, "  • Service AutoStart: %s\n", cfg->auto_start_service ? "YES (systemd)" : "NO");
    fprintf(out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}
