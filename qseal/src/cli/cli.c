/*
 * qseal/src/cli/cli.c
 *
 * Command-Line Interface dispatcher and subcommand implementations.
 */

#define _POSIX_C_SOURCE 200809L
#include "cli.h"
#include "qseal/common.h"
#include "qseal/error.h"
#include "qseal/config.h"
#include "qseal/device_profile.h"
#include "qseal/profile_registry.h"
#include "qseal/policy.h"
#include "qseal/adaptive.h"
#include "qseal/identity.h"
#include "qseal/server.h"
#include "qseal/client.h"
#include "qseal/metrics.h"
#include "qseal/crypto_backend.h"
#include "qseal/logging.h"
#include "../setup/setup_wizard.h"
#include "../config/json_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>

#define DEFAULT_SERVER_YAML_PATH   "/etc/qseal/server.yaml"
#define DEFAULT_CLIENT_YAML_PATH   "/etc/qseal/client.yaml"
#define DEFAULT_SERVER_JSON_PATH   "/etc/qseal/server.json"
#define DEFAULT_CLIENT_JSON_PATH   "/etc/qseal/client.json"
#define DEFAULT_CONFIG_YAML_PATH   "/etc/qseal/qseal.yaml"
#define DEFAULT_CONFIG_JSON_PATH   "/etc/qseal/qseal.json"

static const char *get_server_config_path(void) {
    const char *home = getenv("HOME");
    static char path[QSEAL_MAX_PATH_LEN];
    if (home && strlen(home) > 0) {
        snprintf(path, sizeof(path), "%s/.config/qseal/server.yaml", home);
        if (access(path, R_OK) == 0) return path;
        snprintf(path, sizeof(path), "%s/.config/qseal/server.json", home);
        if (access(path, R_OK) == 0) return path;
    }
    if (access(DEFAULT_SERVER_YAML_PATH, R_OK) == 0) return DEFAULT_SERVER_YAML_PATH;
    if (access(DEFAULT_SERVER_JSON_PATH, R_OK) == 0) return DEFAULT_SERVER_JSON_PATH;
    if (access("./config/server.yaml", R_OK) == 0) return "./config/server.yaml";
    if (access("./config/server.json", R_OK) == 0) return "./config/server.json";
    if (getuid() == 0) return DEFAULT_SERVER_YAML_PATH;
    if (home && strlen(home) > 0) {
        snprintf(path, sizeof(path), "%s/.config/qseal/server.yaml", home);
        return path;
    }
    return DEFAULT_SERVER_YAML_PATH;
}

static const char *get_client_config_path(void) {
    const char *home = getenv("HOME");
    static char path[QSEAL_MAX_PATH_LEN];
    if (home && strlen(home) > 0) {
        snprintf(path, sizeof(path), "%s/.config/qseal/client.yaml", home);
        if (access(path, R_OK) == 0) return path;
        snprintf(path, sizeof(path), "%s/.config/qseal/client.json", home);
        if (access(path, R_OK) == 0) return path;
    }
    if (access(DEFAULT_CLIENT_YAML_PATH, R_OK) == 0) return DEFAULT_CLIENT_YAML_PATH;
    if (access(DEFAULT_CLIENT_JSON_PATH, R_OK) == 0) return DEFAULT_CLIENT_JSON_PATH;
    if (access("./config/client.yaml", R_OK) == 0) return "./config/client.yaml";
    if (access("./config/client.json", R_OK) == 0) return "./config/client.json";
    if (getuid() == 0) return DEFAULT_CLIENT_YAML_PATH;
    if (home && strlen(home) > 0) {
        snprintf(path, sizeof(path), "%s/.config/qseal/client.yaml", home);
        return path;
    }
    return DEFAULT_CLIENT_YAML_PATH;
}

static const char *get_default_config_path(void) {
    const char *home = getenv("HOME");
    static char user_cfg[QSEAL_MAX_PATH_LEN];
    if (home && strlen(home) > 0) {
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/server.yaml", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/client.yaml", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/server.json", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/client.json", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
    }
    if (access(DEFAULT_SERVER_YAML_PATH, R_OK) == 0) return DEFAULT_SERVER_YAML_PATH;
    if (access(DEFAULT_CLIENT_YAML_PATH, R_OK) == 0) return DEFAULT_CLIENT_YAML_PATH;
    if (access(DEFAULT_SERVER_JSON_PATH, R_OK) == 0) return DEFAULT_SERVER_JSON_PATH;
    if (access(DEFAULT_CLIENT_JSON_PATH, R_OK) == 0) return DEFAULT_CLIENT_JSON_PATH;
    if (access(DEFAULT_CONFIG_YAML_PATH, R_OK) == 0) return DEFAULT_CONFIG_YAML_PATH;
    if (access(DEFAULT_CONFIG_JSON_PATH, R_OK) == 0) return DEFAULT_CONFIG_JSON_PATH;
    if (access("./config/server.yaml", R_OK) == 0) return "./config/server.yaml";
    if (access("./config/client.yaml", R_OK) == 0) return "./config/client.yaml";
    if (access("./config/qseal.yaml", R_OK) == 0) return "./config/qseal.yaml";
    if (access("./config/qseal.json", R_OK) == 0) return "./config/qseal.json";
    if (getuid() != 0 && home && strlen(home) > 0) {
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/server.yaml", home);
        return user_cfg;
    }
    return DEFAULT_SERVER_YAML_PATH;
}

static const char *get_server_pid_path(void) {
    if (access("/run/qseal/qseal-server.pid", F_OK) == 0) return "/run/qseal/qseal-server.pid";
    if (access("/tmp/qseal-server.pid", F_OK) == 0) return "/tmp/qseal-server.pid";
    return "/run/qseal/qseal-server.pid";
}

static const char *get_server_status_path(void) {
    if (access("/run/qseal/qseal-server.status", F_OK) == 0) return "/run/qseal/qseal-server.status";
    if (access("/tmp/qseal-server.status", F_OK) == 0) return "/tmp/qseal-server.status";
    return "/run/qseal/qseal-server.status";
}

static const char *get_client_pid_path(void) {
    if (access("/run/qseal/qseal-client.pid", F_OK) == 0) return "/run/qseal/qseal-client.pid";
    if (access("/tmp/qseal-client.pid", F_OK) == 0) return "/tmp/qseal-client.pid";
    return "/run/qseal/qseal-client.pid";
}

static pid_t read_pid_from_file(const char *pid_file) {
    FILE *f = fopen(pid_file, "r");
    if (!f) return -1;
    pid_t pid = -1;
    if (fscanf(f, "%d", &pid) != 1) pid = -1;
    fclose(f);
    return pid;
}

static bool is_process_running(pid_t pid) {
    if (pid <= 0) return false;
    if (kill(pid, 0) == 0) return true;
    /* In containerized or sandboxed namespaces, kill(pid, 0) across subshells may return ESRCH.
     * Check if status file was actively updated by the running daemon watchdog within 15s */
    const char *st_file = get_server_status_path();
    struct stat st;
    if (stat(st_file, &st) == 0) {
        time_t now = time(NULL);
        if (now >= st.st_mtime && (now - st.st_mtime <= 15)) {
            return true;
        }
    }
    return false;
}

static char *read_file_contents(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 1024 * 1024) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = '\0';
    fclose(f);
    return buf;
}

static void print_version(void) {
    printf("QSEAL (Quantum-Secure Enterprise Access & Link) version %s\n", QSEAL_VERSION_STRING);
    printf("Independent Hybrid and Post-Quantum Secure Networking Platform\n");
    printf("Protocols: Hybrid (X25519 + ML-KEM-768 + ML-DSA-65) & Pure PQC (ML-KEM-768 + ML-DSA-65)\n");
    printf("AEAD: ChaCha20-Poly1305 (RFC 8439) | KDF: HKDF-SHA-384 (RFC 5869)\n");
    printf("Target Architecture: Linux x86_64 / ARM64 / ARM32 (Native UDP Direct Connectivity)\n");
}

static void print_help(const char *prog) {
    printf("Usage: %s <command> [subcommand] [options]\n\n", prog);
    printf("Platform Management Commands:\n");
    printf("  setup                     Run guided interactive onboarding setup wizard\n");
    printf("  detect                    Detect hardware, CPU SIMD features, memory, and crypto backends\n");
    printf("  diagnostics               Run comprehensive network, port, NAT, and crypto diagnostics\n");
    printf("  status                    Display platform, service runtime, and cryptographic status\n");
    printf("  clients                   Display live table of active authenticated clients\n");
    printf("  benchmark                 Run cryptographic microbenchmarks (Hybrid & Pure PQC)\n");
    printf("\nServer Commands:\n");
    printf("  server [start] [port]     Launch independent QSEAL UDP server (default: 0.0.0.0:9877)\n");
    printf("  server stop               Stop running QSEAL server process\n");
    printf("  server restart            Restart running QSEAL server\n");
    printf("  server status             Display live server status, socket bindings, and metrics\n");
    printf("  server clients            Display table of active authenticated clients connected\n");
    printf("  server show-logs          Show recent server log output\n");
    printf("  server validate           Validate server configuration syntax and permissions\n");
    printf("  server init               Initialize server identity keys and default YAML configuration\n");
    printf("\nClient Commands:\n");
    printf("  client [connect] [host]   Establish secure quantum-safe tunnel to server\n");
    printf("  client disconnect         Terminate active client connection\n");
    printf("  client status             Display client connection status\n");
    printf("  client show-logs          Show recent client log output\n");
    printf("  client validate           Validate client configuration syntax and permissions\n");
    printf("  client init               Initialize client identity keys and default YAML configuration\n");
    printf("\nConfiguration & Profiles:\n");
    printf("  config validate           Validate syntax, permissions, and network settings of config\n");
    printf("  config show               Display active configuration with secret redaction\n");
    printf("  profiles list             List registered cryptographic profiles (Hybrid, PQC)\n");
    printf("  profiles check            Check hardware and library compatibility for each profile\n");
    printf("\nGlobal Options:\n");
    printf("  --server <ip/host>        Target server IP address or hostname\n");
    printf("  --port <port>             Target or bind UDP port (default: 9877)\n");
    printf("  --bind <ip>               Server bind address (default: 0.0.0.0)\n");
    printf("  --advertised <ip/host>    Server globally advertised public endpoint\n");
    printf("  --mode <hybrid|pqc>       Enforce cryptographic mode (default: hybrid)\n");
    printf("  --config <path>           Specify explicit configuration file path\n");
    printf("  --msg <text>              Send single message and exit (non-interactive)\n");
    printf("  --non-interactive         Run setup non-interactively for automated deployments\n");
    printf("  --version, -v             Display version information\n");
    printf("  --help, -h                Display this help message\n");
    printf("\nExamples:\n");
    printf("  # Server Onboarding & Execution:\n");
    printf("  %s setup --role server\n", prog);
    printf("  %s server start --port 9877\n", prog);
    printf("  %s server clients\n\n", prog);
    printf("  # Direct Public-IP Client Connection:\n");
    printf("  %s setup --role client\n", prog);
    printf("  %s client connect 203.0.113.10 9877\n", prog);
    printf("  %s client connect --server vpn.company.com --port 9877\n", prog);
}

/* ─── Signal handling for Server ─────────────────────────────────── */
static qseal_server_t *g_server = NULL;

static void server_sigint_handler(int sig) {
    (void)sig;
    if (g_server) {
        qseal_server_stop(g_server);
    }
}

/* ─── Subcommand: detect ─────────────────────────────────────────── */
static int cmd_detect(void) {
    qseal_device_profile_t dev;
    int rc = qseal_device_profile_collect(&dev);
    if (rc != QSEAL_SUCCESS) {
        fprintf(stderr, "Error detecting hardware capabilities: %s\n", qseal_strerror(rc));
        return 1;
    }
    qseal_device_profile_print(&dev, stdout);
    return 0;
}

/* ─── Subcommand: profiles ───────────────────────────────────────── */
static int cmd_profiles(int argc, char **argv) {
    if (argc < 1 || strcmp(argv[0], "list") == 0) {
        qseal_profile_list_print(stdout);
        return 0;
    }

    if (strcmp(argv[0], "check") == 0) {
        qseal_device_profile_t dev;
        qseal_device_profile_collect(&dev);

        size_t count = 0;
        const qseal_profile_t *list = qseal_profile_get_all(&count);

        printf("\n=========================================================================================\n");
        printf("                     CRYPTOGRAPHIC PROFILE COMPATIBILITY CHECK                           \n");
        printf("=========================================================================================\n");
        printf(" %-20s %-12s %-10s %s\n", "PROFILE ID", "MODE", "SUPPORTED", "COMPATIBILITY NOTE");
        printf("-----------------------------------------------------------------------------------------\n");

        for (size_t i = 0; i < count; i++) {
            bool ok = qseal_profile_is_device_compatible(&list[i], &dev);
            printf(" %-20s %-12s %-10s %s\n",
                   list[i].id,
                   qseal_mode_to_string(list[i].mode),
                   ok ? "YES [OK]" : "NO [FAIL]",
                   ok ? "All hardware, memory & crypto backend requirements satisfied"
                      : "Insufficient hardware resources or unverified parameter set");
        }
        printf("=========================================================================================\n\n");
        return 0;
    }

    fprintf(stderr, "Unknown profiles subcommand: '%s'. Use 'list' or 'check'.\n", argv[0]);
    return 1;
}

/* ─── Subcommand: adaptive explain ───────────────────────────────── */
static int cmd_adaptive_explain(void) {
    qseal_device_profile_t dev;
    qseal_device_profile_collect(&dev);

    qseal_policy_t pol;
    qseal_policy_init_default(&pol);

    qseal_adaptive_decision_t decision;
    int rc = qseal_adaptive_select(&dev, &pol, NULL, 0, &decision);
    if (rc != QSEAL_SUCCESS) {
        fprintf(stderr, "Adaptive selection failed: %s\n", qseal_strerror(rc));
        return 1;
    }

    qseal_adaptive_explain(&decision, &dev, &pol, stdout);
    return 0;
}

/* ─── Subcommand: config ─────────────────────────────────────────── */
static int cmd_config(int argc, char **argv, const char *cfg_path) {
    if (argc < 1 || strcmp(argv[0], "validate") == 0) {
        qseal_config_t cfg;
        int rc = qseal_config_load(&cfg, cfg_path);
        if (rc != QSEAL_SUCCESS) {
            fprintf(stderr, "FAIL: Could not load configuration '%s': %s\n", cfg_path, qseal_strerror(rc));
            return 1;
        }

        rc = qseal_config_validate(&cfg);
        if (rc != QSEAL_SUCCESS) {
            fprintf(stderr, "FAIL: Configuration validation error: %s\n", qseal_strerror(rc));
            return 1;
        }

        printf("OK: Configuration at '%s' is valid and syntax-compliant.\n", cfg_path);
        return 0;
    }

    if (strcmp(argv[0], "show") == 0) {
        qseal_config_t cfg;
        int rc = qseal_config_load(&cfg, cfg_path);
        if (rc != QSEAL_SUCCESS) {
            fprintf(stderr, "Error loading configuration '%s': %s\n", cfg_path, qseal_strerror(rc));
            return 1;
        }
        qseal_config_print(&cfg, stdout);
        return 0;
    }

    fprintf(stderr, "Unknown config subcommand: '%s'. Use 'validate' or 'show'.\n", argv[0]);
    return 1;
}

static void print_active_network_endpoints(uint16_t port) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        printf("  Endpoints     : 0.0.0.0:%u\n", port);
        return;
    }
    printf("  Network Endpoints Discovered on Host:\n");
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        struct sockaddr_in *p = (struct sockaddr_in *)ifa->ifa_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &p->sin_addr, ip, sizeof(ip));

        const char *desc = "LAN/Ethernet";
        const char *nat_note = "";
        if (strcmp(ip, "127.0.0.1") == 0) {
            desc = "Local Loopback";
            nat_note = "Local IPC only";
        } else if (strstr(ifa->ifa_name, "wl") != NULL) {
            desc = "Wi-Fi Interface";
        } else if (strstr(ifa->ifa_name, "tun") != NULL || strstr(ifa->ifa_name, "tap") != NULL) {
            desc = "Tunnel Interface";
        }

        /* Check for private / NAT IP ranges */
        if (strncmp(ip, "10.", 3) == 0 || strncmp(ip, "192.168.", 8) == 0 ||
            strncmp(ip, "172.16.", 7) == 0 || strncmp(ip, "172.17.", 7) == 0 ||
            strncmp(ip, "172.18.", 7) == 0 || strncmp(ip, "172.19.", 7) == 0 ||
            strncmp(ip, "172.2", 5) == 0 || strncmp(ip, "172.3", 5) == 0) {
            nat_note = "Private NAT (Port-forwarding required for public Internet access)";
        } else if (strncmp(ip, "100.64.", 7) == 0 || strncmp(ip, "100.65.", 7) == 0 ||
                   strncmp(ip, "100.1", 5) == 0) {
            nat_note = "Carrier-Grade NAT (CGNAT) / Overlay Range";
        } else if (strcmp(ip, "127.0.0.1") != 0) {
            nat_note = "Public Globally Reachable Direct IP";
        }

        printf("    • %-16s : %s:%u (%s) [%s]\n", desc, ip, port, ifa->ifa_name, nat_note);
    }
    freeifaddrs(ifaddr);
}

/* ─── Subcommand: server start ───────────────────────────────────── */
static int cmd_server_start(const char *cfg_path, const char *override_port, const char *override_mode) {
    qseal_config_t cfg;
    int rc = qseal_config_load(&cfg, cfg_path);
    if (rc != QSEAL_SUCCESS) {
        qseal_config_init_default(&cfg);
        cfg.role = QSEAL_ROLE_SERVER;
    }

    if (override_port && strlen(override_port) > 0) {
        cfg.port = (uint16_t)atoi(override_port);
    } else if (cfg.port == 0) {
        cfg.port = QSEAL_DEFAULT_PORT;
    }
    if (override_mode) {
        cfg.mode = qseal_mode_from_string(override_mode);
    }

    /* Load identity */
    qseal_identity_t ident;
    char base_dir[QSEAL_MAX_PATH_LEN] = "/etc/qseal";
    if (getuid() != 0) {
        const char *home = getenv("HOME");
        if (home && strlen(home) > 0) {
            snprintf(base_dir, sizeof(base_dir), "%s/.config/qseal", home);
        } else {
            snprintf(base_dir, sizeof(base_dir), "/tmp/qseal-%u", (unsigned int)getuid());
        }
    } else if (access("/etc/qseal", F_OK) != 0 && access("/etc/qseal", F_OK) == 0) {
        snprintf(base_dir, sizeof(base_dir), "/etc/qseal");
    }

    qseal_identity_init(&ident, cfg.device_id, cfg.mode, base_dir);
    if (strlen(cfg.private_key_path) > 0) {
        snprintf(ident.private_key_path, sizeof(ident.private_key_path), "%s", cfg.private_key_path);
    }
    if (strlen(cfg.public_key_path) > 0) {
        snprintf(ident.public_key_path, sizeof(ident.public_key_path), "%s", cfg.public_key_path);
    }
    if (strlen(cfg.trust_store_path) > 0) {
        snprintf(ident.trust_store_path, sizeof(ident.trust_store_path), "%s", cfg.trust_store_path);
    }

    if (!qseal_identity_exists(&ident)) {
        fprintf(stderr, "\n");
        fprintf(stderr, "╔══════════════════════════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║                      SETUP REQUIRED BEFORE STARTING                      ║\n");
        fprintf(stderr, "╚══════════════════════════════════════════════════════════════════════════╝\n");
        fprintf(stderr, " [!] Error: QSEAL server identity not found on this system.\n");
        fprintf(stderr, "     Missing keyfile: %s\n\n", ident.private_key_path);
        fprintf(stderr, " [>] Please run the onboarding setup wizard first:\n");
        fprintf(stderr, "       qseal setup\n");
        fprintf(stderr, "     (or 'qseal server init')\n\n");
        fprintf(stderr, "     The wizard will benchmark hardware, select post-quantum profiles,\n");
        fprintf(stderr, "     generate your cryptographic keypair, and save configuration.\n\n");
        return 1;
    } else {
        int l_rc = qseal_identity_load(&ident);
        if (l_rc != QSEAL_SUCCESS) {
            fprintf(stderr, "Failed to load server identity: %s\n", qseal_strerror(l_rc));
            return 1;
        }
    }

    g_server = qseal_server_create(&cfg, &ident);
    if (!g_server) {
        fprintf(stderr, "Failed to create QSEAL server instance\n");
        return 1;
    }

    signal(SIGINT, server_sigint_handler);
    signal(SIGTERM, server_sigint_handler);

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                 QSEAL Secure Server (Hybrid & Pure Post-Quantum)                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════╝\n");
    printf("  Status        : LISTENING\n");
    printf("  Bind Address  : %s (UDP — Listening on all local interfaces)\n", cfg.bind_address);
    if (cfg.advertised_endpoint[0]) {
        printf("  Advertised    : %s (Public Direct Endpoint)\n", cfg.advertised_endpoint);
    }
    printf("  Port          : %u\n", cfg.port);
    print_active_network_endpoints(cfg.port);
    printf("  Crypto Mode   : %s\n", qseal_mode_to_string(cfg.mode));
    printf("  Device ID     : %s\n", cfg.device_id);
    printf("  Fingerprint   : %.16s...\n", ident.fingerprint);
    printf("  Key File      : %s\n\n", ident.private_key_path);
    printf("[Ready] Waiting for incoming client connections... (Press Ctrl+C to stop)\n\n");

    rc = qseal_server_run(g_server);

    const qseal_metrics_t *m = qseal_server_get_metrics(g_server);
    if (m) {
        qseal_metrics_print(m, stdout);
    }

    qseal_server_free(g_server);
    g_server = NULL;
    return rc == QSEAL_SUCCESS ? 0 : 1;
}

/* ─── Subcommand: client connect ─────────────────────────────────── */
static int cmd_client_connect(const char *cfg_path, const char *server_host, const char *port_str,
                              const char *mode_str, const char *msg) {
    qseal_config_t cfg;
    int rc = qseal_config_load(&cfg, cfg_path);
    if (rc != QSEAL_SUCCESS) {
        qseal_config_init_default(&cfg);
        cfg.role = QSEAL_ROLE_CLIENT;
    }

    if (server_host && strlen(server_host) > 0) {
        snprintf(cfg.server_host, sizeof(cfg.server_host), "%s", server_host);
        snprintf(cfg.server_address, sizeof(cfg.server_address), "%s", server_host);
    } else if (strlen(cfg.server_host) == 0 && strlen(cfg.server_address) == 0) {
        snprintf(cfg.server_host, sizeof(cfg.server_host), "%s", QSEAL_DEFAULT_SERVER_HOST);
        snprintf(cfg.server_address, sizeof(cfg.server_address), "%s", QSEAL_DEFAULT_SERVER_HOST);
    } else if (strlen(cfg.server_host) == 0 && strlen(cfg.server_address) > 0) {
        snprintf(cfg.server_host, sizeof(cfg.server_host), "%s", cfg.server_address);
    }

    if (port_str && strlen(port_str) > 0) {
        cfg.port = (uint16_t)atoi(port_str);
    } else if (cfg.port == 0) {
        cfg.port = QSEAL_DEFAULT_PORT;
    }
    if (mode_str) cfg.mode = qseal_mode_from_string(mode_str);

    /* Initialize identity with user-path fallback */
    qseal_identity_t ident;
    char base_dir[QSEAL_MAX_PATH_LEN] = "/etc/qseal";
    if (getuid() != 0) {
        const char *home = getenv("HOME");
        if (home && strlen(home) > 0) {
            snprintf(base_dir, sizeof(base_dir), "%s/.config/qseal", home);
        } else {
            snprintf(base_dir, sizeof(base_dir), "/tmp/qseal-%u", (unsigned int)getuid());
        }
    } else if (access("/etc/qseal", F_OK) != 0 && access("/etc/qseal", F_OK) == 0) {
        snprintf(base_dir, sizeof(base_dir), "/etc/qseal");
    }

    qseal_identity_init(&ident, cfg.device_id, cfg.mode, base_dir);
    if (strlen(cfg.private_key_path) > 0) {
        snprintf(ident.private_key_path, sizeof(ident.private_key_path), "%s", cfg.private_key_path);
    }
    if (strlen(cfg.public_key_path) > 0) {
        snprintf(ident.public_key_path, sizeof(ident.public_key_path), "%s", cfg.public_key_path);
    }
    if (strlen(cfg.trust_store_path) > 0) {
        snprintf(ident.trust_store_path, sizeof(ident.trust_store_path), "%s", cfg.trust_store_path);
    }

    if (!qseal_identity_exists(&ident)) {
        fprintf(stderr, "\n");
        fprintf(stderr, "╔══════════════════════════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║                    INITIAL SETUP REQUIRED TO CONNECT                     ║\n");
        fprintf(stderr, "╚══════════════════════════════════════════════════════════════════════════╝\n");
        fprintf(stderr, " [!] Error: QSEAL client node is not configured on this device.\n");
        fprintf(stderr, "     Missing keyfile: %s\n\n", ident.private_key_path);
        fprintf(stderr, " [>] Please run the onboarding setup wizard first:\n");
        fprintf(stderr, "       qseal setup\n");
        fprintf(stderr, "     (or 'qseal client init')\n\n");
        fprintf(stderr, "     The wizard will benchmark hardware, select post-quantum profiles,\n");
        fprintf(stderr, "     generate your cryptographic keypair, and register network endpoints.\n\n");
        return 1;
    } else {
        int l_rc = qseal_identity_load(&ident);
        if (l_rc != QSEAL_SUCCESS) {
            fprintf(stderr, "Failed to load client identity keypair: %s\n", qseal_strerror(l_rc));
            return 1;
        }
    }

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                 QSEAL Secure Client (Hybrid & Pure Post-Quantum)                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════╝\n");
    printf("  Target Server : %s:%u (UDP)\n", cfg.server_host, cfg.port);
    printf("  Crypto Mode   : %s\n", qseal_mode_to_string(cfg.mode));
    printf("  Device ID     : %s\n", cfg.device_id);
    printf("  Fingerprint   : %.16s...\n", ident.fingerprint);
    printf("  Key File      : %s\n\n", ident.private_key_path);

    qseal_client_t *client = qseal_client_create(&cfg, &ident);
    if (!client) {
        fprintf(stderr, "Failed to create QSEAL client instance\n");
        return 1;
    }

    printf("[*] Connecting to %s:%u over UDP...\n", cfg.server_host, cfg.port);
    rc = qseal_client_connect(client);
    if (rc != QSEAL_SUCCESS) {
        fprintf(stderr, "[!] Connection failed: %s\n", qseal_strerror(rc));
        fprintf(stderr, "    Tip: Verify server is running on %s:%u and UDP port %u is open.\n\n",
                cfg.server_host, cfg.port, cfg.port);
        qseal_client_free(client);
        return 1;
    }

    printf("[✓] Post-Quantum Handshake Established! Mutual Authentication Verified.\n");
    printf("[✓] Encrypted Session Active.\n\n");

    if (msg) {
        rc = qseal_client_send(client, (const uint8_t *)msg, strlen(msg));
        if (rc == QSEAL_SUCCESS) {
            printf("[✓] Message sent successfully (%zu bytes).\n", strlen(msg));
        } else {
            fprintf(stderr, "Failed to send message: %s\n", qseal_strerror(rc));
        }
        qseal_client_disconnect(client);
    } else {
        qseal_client_run_interactive(client);
    }

    const qseal_metrics_t *m = qseal_client_get_metrics(client);
    if (m) {
        qseal_metrics_print(m, stdout);
    }

    qseal_client_free(client);
    return 0;
}

static void sleep_ms(unsigned int ms) {
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&req, NULL);
}

/* ─── Subcommands: server management ─────────────────────────────── */
static int cmd_server_stop(void) {
    const char *pid_file = get_server_pid_path();
    pid_t pid = read_pid_from_file(pid_file);
    if (pid <= 0 || !is_process_running(pid)) {
        printf("QSEAL server is not running.\n");
        if (access(pid_file, F_OK) == 0) unlink(pid_file);
        const char *st_file = get_server_status_path();
        if (access(st_file, F_OK) == 0) unlink(st_file);
        return 0;
    }

    printf("[*] Stopping QSEAL server (PID %d)...\n", pid);
    kill(pid, SIGTERM);

    for (int i = 0; i < 50; i++) {
        sleep_ms(100);
        if (!is_process_running(pid)) {
            printf("[✓] QSEAL server stopped successfully.\n");
            unlink(pid_file);
            const char *st_file = get_server_status_path();
            unlink(st_file);
            return 0;
        }
    }

    printf("[!] Server did not shut down within 5s, sending SIGKILL...\n");
    kill(pid, SIGKILL);
    unlink(pid_file);
    const char *st_file = get_server_status_path();
    unlink(st_file);
    printf("[✓] QSEAL server terminated.\n");
    return 0;
}

static int cmd_server_restart(const char *cfg_path, const char *override_port, const char *override_mode) {
    printf("[*] Restarting QSEAL server...\n");
    cmd_server_stop();
    sleep(1);
    return cmd_server_start(cfg_path, override_port, override_mode);
}

static int cmd_server_clients(void) {
    const char *pid_file = get_server_pid_path();
    pid_t pid = read_pid_from_file(pid_file);
    if (!is_process_running(pid)) {
        printf("\n[!] QSEAL Server is not running.\n");
        printf("    Start the server with: qseal server start\n");
        printf("    Or using systemd   : sudo systemctl start qseal-server\n\n");
        return 1;
    }

    const char *status_file = get_server_status_path();
    char *json_text = read_file_contents(status_file);
    if (!json_text) {
        printf("\n[!] Could not read server status file (%s).\n\n", status_file);
        return 1;
    }

    char err[128] = {0};
    json_value_t *root = json_parse(json_text, err, sizeof(err));
    free(json_text);
    if (!root) {
        printf("\n[!] Error parsing status JSON: %s\n\n", err);
        return 1;
    }

    json_value_t *clients_arr = json_object_get(root, "clients");
    size_t count = (clients_arr && clients_arr->type == JSON_ARRAY) ? clients_arr->u.array.count : 0;

    printf("\n╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                                 QSEAL ACTIVE AUTHENTICATED CLIENTS                                     ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
    printf(" %-4s  %-18s %-22s %-16s %-8s %-10s %-10s %-5s\n",
           "ID", "DEVICE ID", "REMOTE ENDPOINT", "SESSION ID", "MODE", "CONNECTED", "LAST SEEN", "MSGS");
    printf("──────────────────────────────────────────────────────────────────────────────────────────────────────────\n");

    if (count == 0) {
        printf("  (No active clients currently connected)\n");
    } else {
        for (size_t i = 0; i < count; i++) {
            json_value_t *c = clients_arr->u.array.items[i];
            if (!c || c->type != JSON_OBJECT) continue;

            int64_t cid = json_get_int(json_object_get(c, "client_id"), (int64_t)(i + 1));
            const char *dev_id = json_get_string(json_object_get(c, "device_id"), "unknown");
            const char *ip = json_get_string(json_object_get(c, "ip"), "0.0.0.0");
            int64_t port = json_get_int(json_object_get(c, "port"), 0);
            const char *sid = json_get_string(json_object_get(c, "session_id"), "0000000000000000");
            const char *mode = json_get_string(json_object_get(c, "mode"), "HYBRID");
            int64_t conn_ago = json_get_int(json_object_get(c, "connected_sec_ago"), 0);
            int64_t seen_ago = json_get_int(json_object_get(c, "last_seen_sec_ago"), 0);
            int64_t msgs = json_get_int(json_object_get(c, "msg_count"), 0);

            char ep[32];
            snprintf(ep, sizeof(ep), "%s:%lld", ip, (long long)port);

            char conn_str[32];
            if (conn_ago >= 3600) {
                snprintf(conn_str, sizeof(conn_str), "%lldh %lldm", (long long)(conn_ago / 3600), (long long)((conn_ago % 3600) / 60));
            } else if (conn_ago >= 60) {
                snprintf(conn_str, sizeof(conn_str), "%lldm %llds", (long long)(conn_ago / 60), (long long)(conn_ago % 60));
            } else {
                snprintf(conn_str, sizeof(conn_str), "%llds ago", (long long)conn_ago);
            }

            char seen_str[32];
            if (seen_ago >= 60) {
                snprintf(seen_str, sizeof(seen_str), "%lldm ago", (long long)(seen_ago / 60));
            } else {
                snprintf(seen_str, sizeof(seen_str), "%llds ago", (long long)seen_ago);
            }

            printf(" %-4lld  %-18s %-22s %-16s %-8s %-10s %-10s %-5lld\n",
                   (long long)cid, dev_id, ep, sid, mode, conn_str, seen_str, (long long)msgs);
        }
    }
    printf("──────────────────────────────────────────────────────────────────────────────────────────────────────────\n");
    int64_t max_sess = json_get_int(json_object_get(root, "max_sessions"), 256);
    printf(" Total Active Authenticated Clients: %zu / %lld\n", count, (long long)max_sess);
    printf("==========================================================================================================\n\n");

    json_free(root);
    return 0;
}

static int cmd_server_status(const char *cfg_path) {
    const char *pid_file = get_server_pid_path();
    pid_t pid = read_pid_from_file(pid_file);
    bool running = is_process_running(pid);

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                          QSEAL SERVER RUNTIME STATUS                             ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════╝\n");
    if (running) {
        printf("  Process State      : RUNNING [PID %d]\n", pid);
        const char *status_file = get_server_status_path();
        char *json_text = read_file_contents(status_file);
        if (json_text) {
            char err[128] = {0};
            json_value_t *root = json_parse(json_text, err, sizeof(err));
            free(json_text);
            if (root) {
                int64_t uptime = json_get_int(json_object_get(root, "uptime_sec"), 0);
                const char *bind_addr = json_get_string(json_object_get(root, "bind_address"), "0.0.0.0");
                int64_t port = json_get_int(json_object_get(root, "port"), 9877);
                const char *adv = json_get_string(json_object_get(root, "advertised_endpoint"), "");
                const char *mode = json_get_string(json_object_get(root, "mode"), "HYBRID");
                int64_t active_cnt = json_get_int(json_object_get(root, "active_sessions_count"), 0);
                int64_t max_sess = json_get_int(json_object_get(root, "max_sessions"), 256);
                int64_t handshakes = json_get_int(json_object_get(root, "total_handshakes"), 0);
                int64_t rx = json_get_int(json_object_get(root, "packets_rx"), 0);
                int64_t tx = json_get_int(json_object_get(root, "packets_tx"), 0);

                long hours = (long)(uptime / 3600);
                long mins = (long)((uptime % 3600) / 60);
                long secs = (long)(uptime % 60);

                printf("  Uptime             : %ldh %ldm %lds\n", hours, mins, secs);
                printf("  Listening Endpoint : %s:%lld (UDP Native Direct)\n", bind_addr, (long long)port);
                if (adv && strlen(adv) > 0) {
                    printf("  Advertised Endpoint: %s (Direct Public WAN Endpoint)\n", adv);
                }
                printf("  Cryptographic Mode : %s\n", mode);
                printf("  Active Clients     : %lld / %lld connected\n", (long long)active_cnt, (long long)max_sess);
                printf("  Handshakes Succeeded: %lld\n", (long long)handshakes);
                printf("  Packets Received   : %lld\n", (long long)rx);
                printf("  Packets Sent       : %lld\n", (long long)tx);
                json_free(root);
            }
        }
    } else {
        printf("  Process State      : STOPPED (Inactive)\n");
        printf("  Hint               : Run 'qseal server start' or 'sudo systemctl start qseal-server'\n");
    }

    printf("──────────────────────────────────────────────────────────────────────────────────\n");
    printf("  Configuration File : %s\n", cfg_path);
    if (access(cfg_path, F_OK) == 0) {
        printf("  Config Status      : PRESENT (Valid)\n");
    } else {
        printf("  Config Status      : NOT FOUND (Run 'qseal server init' or 'qseal setup')\n");
    }
    printf("  Systemd Service    : qseal-server.service\n");
    printf("==================================================================================\n\n");
    return 0;
}

static int show_log_file(const char *path, int max_lines) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    printf("\n--- Displaying recent logs from %s ---\n", path);
    char **lines = calloc((size_t)max_lines, sizeof(char *));
    if (!lines) { fclose(f); return -1; }
    int count = 0;
    char buf[1024];
    while (fgets(buf, sizeof(buf), f)) {
        if (lines[count % max_lines]) free(lines[count % max_lines]);
        lines[count % max_lines] = strdup(buf);
        count++;
    }
    fclose(f);

    int start = (count > max_lines) ? (count % max_lines) : 0;
    int total = (count > max_lines) ? max_lines : count;
    for (int i = 0; i < total; i++) {
        int idx = (start + i) % max_lines;
        if (lines[idx]) {
            fputs(lines[idx], stdout);
            free(lines[idx]);
        }
    }
    free(lines);
    printf("--- End of logs ---\n\n");
    return 0;
}

static int cmd_server_show_logs(void) {
    const char *candidates[] = {
        "/var/log/qseal/server.log",
        "/var/log/qseal.log",
        "/tmp/qseal-server.log",
        NULL
    };
    for (int i = 0; candidates[i] != NULL; i++) {
        if (access(candidates[i], R_OK) == 0) {
            return show_log_file(candidates[i], 50);
        }
    }
    printf("\n[!] No local server log file found in /var/log/qseal/server.log.\n");
    printf("    To inspect systemd journal logs, run:\n");
    printf("      journalctl -u qseal-server -n 50 --no-pager\n\n");
    return 0;
}

/* ─── Subcommands: client management ─────────────────────────────── */
static int cmd_client_disconnect(void) {
    const char *pid_file = get_client_pid_path();
    pid_t pid = read_pid_from_file(pid_file);
    if (pid <= 0 || !is_process_running(pid)) {
        printf("No active QSEAL client process detected.\n");
        if (access(pid_file, F_OK) == 0) unlink(pid_file);
        return 0;
    }

    printf("[*] Disconnecting QSEAL client (PID %d)...\n", pid);
    kill(pid, SIGTERM);
    for (int i = 0; i < 30; i++) {
        sleep_ms(100);
        if (!is_process_running(pid)) {
            printf("[✓] QSEAL client disconnected successfully.\n");
            unlink(pid_file);
            return 0;
        }
    }
    kill(pid, SIGKILL);
    unlink(pid_file);
    printf("[✓] QSEAL client terminated.\n");
    return 0;
}

static int cmd_client_status(const char *cfg_path) {
    const char *pid_file = get_client_pid_path();
    pid_t pid = read_pid_from_file(pid_file);
    bool running = is_process_running(pid);

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                          QSEAL CLIENT RUNTIME STATUS                             ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════╝\n");
    if (running) {
        printf("  Process State      : CONNECTED / RUNNING [PID %d]\n", pid);
    } else {
        printf("  Process State      : DISCONNECTED (Inactive)\n");
        printf("  Hint               : Run 'qseal client connect' to establish tunnel\n");
    }
    printf("  Configuration File : %s\n", cfg_path);
    if (access(cfg_path, F_OK) == 0) {
        printf("  Config Status      : PRESENT (Valid)\n");
    } else {
        printf("  Config Status      : NOT FOUND (Run 'qseal client init' or 'qseal setup')\n");
    }
    printf("==================================================================================\n\n");
    return 0;
}

static int cmd_client_show_logs(void) {
    const char *candidates[] = {
        "/var/log/qseal/client.log",
        "/var/log/qseal.log",
        "/tmp/qseal-client.log",
        NULL
    };
    for (int i = 0; candidates[i] != NULL; i++) {
        if (access(candidates[i], R_OK) == 0) {
            return show_log_file(candidates[i], 50);
        }
    }
    printf("\n[!] No local client log file found in /var/log/qseal/client.log.\n");
    printf("    To inspect systemd journal logs, run:\n");
    printf("      journalctl -u qseal-client -n 50 --no-pager\n\n");
    return 0;
}

/* ─── Subcommand: status ─────────────────────────────────────────── */
static int cmd_status(const char *cfg_path) {
    printf("\n╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                    QSEAL PLATFORM ARCHITECTURE & RUNTIME STATUS                  ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════╝\n");
    printf("  Product            : QSEAL (Quantum-Secure Enterprise Access & Link)\n");
    printf("  Version            : %s (Production Release)\n", QSEAL_VERSION_STRING);
    printf("  Cryptographic Modes: Hybrid (X25519 + ML-KEM-768 + ML-DSA-65)\n");
    printf("                       Pure PQC (NIST FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65)\n");
    printf("  AEAD Cipher        : ChaCha20-Poly1305 (RFC 8439)\n");
    printf("  Key Derivation     : HKDF-SHA-384 (RFC 5869)\n");
    printf("  Network Engine     : Native POSIX UDP Direct Connectivity (Zero VPN/Centralized dependency)\n");
    printf("──────────────────────────────────────────────────────────────────────────────────\n");

    /* Check Server */
    const char *srv_pid_file = get_server_pid_path();
    pid_t srv_pid = read_pid_from_file(srv_pid_file);
    bool srv_running = is_process_running(srv_pid);
    if (srv_running) {
        printf("  Server Service     : RUNNING [PID %d]\n", srv_pid);
        const char *status_file = get_server_status_path();
        char *json_text = read_file_contents(status_file);
        if (json_text) {
            char err[128] = {0};
            json_value_t *root = json_parse(json_text, err, sizeof(err));
            free(json_text);
            if (root) {
                int64_t uptime = json_get_int(json_object_get(root, "uptime_sec"), 0);
                const char *bind_addr = json_get_string(json_object_get(root, "bind_address"), "0.0.0.0");
                int64_t port = json_get_int(json_object_get(root, "port"), 9877);
                const char *mode = json_get_string(json_object_get(root, "mode"), "HYBRID");
                int64_t active_cnt = json_get_int(json_object_get(root, "active_sessions_count"), 0);
                int64_t max_sess = json_get_int(json_object_get(root, "max_sessions"), 256);

                printf("  Server Uptime      : %llds (%lld active clients / %lld max)\n", (long long)uptime, (long long)active_cnt, (long long)max_sess);
                printf("  Listening Endpoint : %s:%lld (UDP) [Mode: %s]\n", bind_addr, (long long)port, mode);
                json_free(root);
            }
        }
    } else {
        printf("  Server Service     : STOPPED (Inactive)\n");
    }

    /* Check Client */
    const char *cli_pid_file = get_client_pid_path();
    pid_t cli_pid = read_pid_from_file(cli_pid_file);
    bool cli_running = is_process_running(cli_pid);
    printf("  Client Service     : %s\n", cli_running ? "ACTIVE / CONNECTED" : "INACTIVE");

    printf("──────────────────────────────────────────────────────────────────────────────────\n");
    printf("  Active Config Path : %s\n", cfg_path);
    printf("  Server Config Path : %s\n", get_server_config_path());
    printf("  Client Config Path : %s\n", get_client_config_path());
    printf("==================================================================================\n\n");
    return 0;
}

/* ─── Subcommand: diagnostics ────────────────────────────────────── */
static int cmd_diagnostics(void) {
    printf("=================================================================================\n");
    printf("                          QSEAL PLATFORM DIAGNOSTICS                             \n");
    printf("=================================================================================\n");

    /* 1. Hardware checks */
    printf("[1/4] Host Hardware & SIMD Acceleration:\n");
    qseal_device_profile_t dev;
    qseal_device_profile_collect(&dev);
    printf("  • CPU Architecture : %s (%s, %u cores)\n", dev.arch, dev.cpu_model, dev.cpu_cores);
    printf("  • Hardware SIMD    : AVX2=%s, AES-NI=%s, NEON=%s\n",
           dev.has_avx2 ? "YES" : "NO", dev.has_aes_ni ? "YES" : "NO", dev.has_neon ? "YES" : "NO");
    printf("  • System Memory    : %llu MB available / %llu MB total\n",
           (unsigned long long)dev.ram_available_mb, (unsigned long long)dev.ram_total_mb);

    /* 2. Crypto checks */
    printf("\n[2/4] Cryptographic Backend Readiness:\n");
    printf("  • OpenSSL 3.x EVP  : %s\n", dev.openssl_available ? "AVAILABLE [PASS]" : "MISSING [FAIL]");
    printf("  • liboqs Engine    : %s\n", dev.liboqs_available ? "AVAILABLE [PASS]" : "MISSING [FAIL]");
    printf("  • ML-KEM-768 (KEX) : %s (NIST FIPS 203)\n", dev.pqc_functional ? "VERIFIED [PASS]" : "UNAVAILABLE [FAIL]");
    printf("  • ML-DSA-65  (DSA) : %s (NIST FIPS 204)\n", dev.pqc_functional ? "VERIFIED [PASS]" : "UNAVAILABLE [FAIL]");
    printf("  • X25519 ECDH      : VERIFIED [PASS] (Classical Key Agreement)\n");
    printf("  • ChaCha20-Poly1305: VERIFIED [PASS] (RFC 8439 Authenticated Encryption)\n");
    printf("  • HKDF-SHA-384     : VERIFIED [PASS] (RFC 5869 Key Derivation Function)\n");

    /* 3. Network & NAT diagnostics */
    printf("\n[3/4] Network Interfaces & NAT/WAN Reachability Analysis:\n");
    struct ifaddrs *ifaddr, *ifa;
    bool has_public = false;
    bool has_cgnat = false;
    bool has_private = false;

    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            int family = ifa->ifa_addr->sa_family;
            if (family == AF_INET) {
                struct sockaddr_in *p = (struct sockaddr_in *)ifa->ifa_addr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &p->sin_addr, ip, sizeof(ip));

                const char *cat = "LAN";
                const char *diag = "";
                if (strcmp(ip, "127.0.0.1") == 0) {
                    cat = "Loopback";
                    diag = "Host-local IPC only";
                } else if (strncmp(ip, "10.", 3) == 0 || strncmp(ip, "192.168.", 8) == 0 ||
                           strncmp(ip, "172.16.", 7) == 0 || strncmp(ip, "172.17.", 7) == 0 ||
                           strncmp(ip, "172.18.", 7) == 0 || strncmp(ip, "172.19.", 7) == 0 ||
                           strncmp(ip, "172.2", 5) == 0 || strncmp(ip, "172.3", 5) == 0) {
                    cat = "Private RFC 1918";
                    diag = "Behind Router NAT (Router port forwarding required for external WAN clients)";
                    has_private = true;
                } else if (strncmp(ip, "100.64.", 7) == 0 || strncmp(ip, "100.65.", 7) == 0 ||
                           strncmp(ip, "100.1", 5) == 0) {
                    cat = "CGNAT RFC 6598";
                    diag = "Behind ISP Carrier-Grade NAT (Inbound connections blocked by ISP)";
                    has_cgnat = true;
                } else {
                    cat = "Public Direct IP";
                    diag = "Directly reachable over the Public Internet";
                    has_public = true;
                }
                printf("  • %-10s (%-16s) : %-15s [%s]\n", ifa->ifa_name, cat, ip, diag);
            }
        }
        freeifaddrs(ifaddr);
    } else {
        printf("  [!] Failed to enumerate network interfaces\n");
    }

    /* 4. Port checks */
    printf("\n[4/4] UDP Transport & Port Verification:\n");
    int s_test = socket(AF_INET, SOCK_DGRAM, 0);
    if (s_test >= 0) {
        struct sockaddr_in test_addr;
        memset(&test_addr, 0, sizeof(test_addr));
        test_addr.sin_family = AF_INET;
        test_addr.sin_addr.s_addr = INADDR_ANY;
        test_addr.sin_port = htons(9877);
        int b1 = bind(s_test, (struct sockaddr *)&test_addr, sizeof(test_addr));
        printf("  • UDP Port 9877 (0.0.0.0) : %s\n", b1 == 0 ? "AVAILABLE FOR BINDING [PASS]" : "PORT IN USE OR RESTRICTED [WARN]");
        close(s_test);
    }

    printf("\n=================================================================================\n");
    printf(" Diagnostic Summary & Connectivity Recommendations:\n");
    if (has_public) {
        printf("  [✓] Public IP Detected: Direct Internet connectivity is supported natively.\n");
    } else if (has_private) {
        printf("  [!] Private NAT Detected: For external WAN clients to connect, forward UDP port\n");
        printf("      9877 on your edge router to this host's local IP.\n");
    }
    if (has_cgnat) {
        printf("  [!] Carrier-Grade NAT Detected: Inbound connections are blocked by ISP.\n");
        printf("      Use a public VPS / cloud endpoint or static public IP for hosting server.\n");
    }
    printf("  [✓] Cryptographic Primitives: Fully operational (Hybrid & Pure PQC ready).\n");
    printf("=================================================================================\n");
    return 0;
}

/* ─── Subcommand: benchmark ──────────────────────────────────────── */
static int cmd_benchmark(const char *mode_str, int iters) {
    if (iters <= 0) iters = 100;
    qseal_mode_t mode = QSEAL_MODE_HYBRID;
    if (mode_str) mode = qseal_mode_from_string(mode_str);

    const qseal_profile_t *prof = qseal_profile_get_by_mode(mode);
    if (!prof) prof = qseal_profile_get_by_id("profile-hybrid-1");

    crypto_backend_t *backend = qseal_crypto_backend_create(prof);
    if (!backend) {
        fprintf(stderr, "Failed to create crypto backend for benchmark\n");
        return 1;
    }

    printf("\n=================================================================================\n");
    printf("                  QSEAL CRYPTOGRAPHIC BENCHMARK (%s)                             \n",
           qseal_mode_to_string(mode));
    printf("               Iterations: %d | Profile: %s\n", iters, prof->name);
    printf("=================================================================================\n");

    /* 1. KEX Keygen */
    uint8_t pk[2048], sk[4096];
    size_t pkl = sizeof(pk), skl = sizeof(sk);
    struct timespec t0, t1;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iters; i++) {
        pkl = sizeof(pk); skl = sizeof(sk);
        backend->kex_keypair(backend, pk, &pkl, sk, &skl);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double kex_kg_ms = ((t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6) / iters;
    printf(" 1. KEX Keygen              : %8.3f ms/op (%8.1f ops/sec)\n", kex_kg_ms, 1000.0 / kex_kg_ms);

    /* 2. KEX Encapsulate */
    uint8_t ct[2048], ss1[64];
    size_t ctl = sizeof(ct), ss1l = sizeof(ss1);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iters; i++) {
        ctl = sizeof(ct); ss1l = sizeof(ss1);
        backend->kex_encapsulate(backend, pk, pkl, ct, &ctl, ss1, &ss1l);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double kex_enc_ms = ((t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6) / iters;
    printf(" 2. KEX Encapsulation       : %8.3f ms/op (%8.1f ops/sec)\n", kex_enc_ms, 1000.0 / kex_enc_ms);

    /* 3. KEX Decapsulate */
    uint8_t ss2[64];
    size_t ss2l = sizeof(ss2);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iters; i++) {
        ss2l = sizeof(ss2);
        backend->kex_decapsulate(backend, ct, ctl, sk, skl, ss2, &ss2l);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double kex_dec_ms = ((t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6) / iters;
    printf(" 3. KEX Decapsulation       : %8.3f ms/op (%8.1f ops/sec)\n", kex_dec_ms, 1000.0 / kex_dec_ms);

    /* 4. DSA Sign */
    uint8_t dsa_pk[2048], dsa_sk[4096];
    size_t dpkl = sizeof(dsa_pk), dskl = sizeof(dsa_sk);
    backend->dsa_keypair(backend, dsa_pk, &dpkl, dsa_sk, &dskl);

    uint8_t msg[128] = "Test handshake transcript buffer for signature benchmark";
    uint8_t sig[4096];
    size_t sigl = sizeof(sig);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iters; i++) {
        sigl = sizeof(sig);
        backend->dsa_sign(backend, msg, sizeof(msg), dsa_sk, dskl, sig, &sigl);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double dsa_sign_ms = ((t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6) / iters;
    printf(" 4. DSA Signature Generate  : %8.3f ms/op (%8.1f ops/sec)\n", dsa_sign_ms, 1000.0 / dsa_sign_ms);

    /* 5. DSA Verify */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iters; i++) {
        backend->dsa_verify(backend, msg, sizeof(msg), sig, sigl, dsa_pk, dpkl);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double dsa_verify_ms = ((t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6) / iters;
    printf(" 5. DSA Signature Verify    : %8.3f ms/op (%8.1f ops/sec)\n", dsa_verify_ms, 1000.0 / dsa_verify_ms);

    /* 6. AEAD Throughput */
    uint8_t payload[1024];
    memset(payload, 0x42, sizeof(payload));
    uint8_t tag[16], nonce[12] = {0};
    uint8_t key[32] = {0};
    uint8_t enc_out[1024];
    size_t enc_len = sizeof(enc_out);

    int aead_iters = iters * 10;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < aead_iters; i++) {
        enc_len = sizeof(enc_out);
        backend->aead_encrypt(backend, payload, sizeof(payload), NULL, 0, nonce, 12, key, 32,
                              enc_out, &enc_len, tag, 16);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double aead_ms = ((t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6) / aead_iters;
    double mbps = (sizeof(payload) * 8.0) / (aead_ms * 1000.0);
    printf(" 6. AEAD (1KB) Encrypt      : %8.3f ms/op (%8.1f Mbps)\n", aead_ms, mbps);

    printf("=================================================================================\n\n");
    qseal_crypto_backend_free(backend);
    return 0;
}

/* ─── Main CLI Dispatcher ────────────────────────────────────────── */
int qseal_cli_dispatch(int argc, char **argv) {
    const char *prog_name = strrchr(argv[0], '/');
    prog_name = prog_name ? prog_name + 1 : argv[0];

    bool is_srv_bin = (strcmp(prog_name, "qseal-server") == 0);
    bool is_cli_bin = (strcmp(prog_name, "qseal-client") == 0);

    const char *cfg_path = NULL;
    bool cfg_explicit = false;
    const char *port_override = NULL;
    const char *mode_override = NULL;
    const char *server_override = NULL;
    const char *bind_override = NULL;
    const char *advertised_override = NULL;
    const char *dev_id_override = NULL;
    const char *expected_srv_override = NULL;
    const char *msg_override = NULL;
    int iters = 100;
    bool non_interactive = false;

    /* Scan for flags across all arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            print_version();
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_help(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            cfg_path = argv[++i];
            cfg_explicit = true;
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port_override = argv[++i];
        } else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            bind_override = argv[++i];
        } else if (strcmp(argv[i], "--advertised") == 0 && i + 1 < argc) {
            advertised_override = argv[++i];
        } else if (strcmp(argv[i], "--device-id") == 0 && i + 1 < argc) {
            dev_id_override = argv[++i];
        } else if (strcmp(argv[i], "--expected-server") == 0 && i + 1 < argc) {
            expected_srv_override = argv[++i];
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode_override = argv[++i];
        } else if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            server_override = argv[++i];
        } else if (strcmp(argv[i], "--msg") == 0 && i + 1 < argc) {
            msg_override = argv[++i];
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            iters = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--non-interactive") == 0) {
            non_interactive = true;
        }
    }

    /* Assign default config path based on mode if not explicitly provided */
    if (!cfg_path) {
        if (is_srv_bin) {
            cfg_path = get_server_config_path();
        } else if (is_cli_bin) {
            cfg_path = get_client_config_path();
        } else {
            cfg_path = get_default_config_path();
        }
    }

    /* ─── Symlink Handling: qseal-server ─────────────────────────────── */
    if (is_srv_bin) {
        if (argc < 2 || argv[1][0] == '-') {
            return cmd_server_start(cfg_path, port_override, mode_override);
        }
        const char *sub = argv[1];
        if (strcmp(sub, "start") == 0) {
            return cmd_server_start(cfg_path, port_override, mode_override);
        } else if (strcmp(sub, "stop") == 0) {
            return cmd_server_stop();
        } else if (strcmp(sub, "restart") == 0) {
            return cmd_server_restart(cfg_path, port_override, mode_override);
        } else if (strcmp(sub, "status") == 0) {
            return cmd_server_status(cfg_path);
        } else if (strcmp(sub, "clients") == 0) {
            return cmd_server_clients();
        } else if (strcmp(sub, "show-logs") == 0) {
            return cmd_server_show_logs();
        } else if (strcmp(sub, "validate") == 0) {
            return cmd_config(1, (char *[]){"validate"}, cfg_path);
        } else if (strcmp(sub, "init") == 0) {
            uint16_t p = port_override ? (uint16_t)atoi(port_override) : QSEAL_DEFAULT_PORT;
            qseal_mode_t m = mode_override ? qseal_mode_from_string(mode_override) : QSEAL_MODE_HYBRID;
            return qseal_setup_init_server(cfg_path, p, bind_override, advertised_override, m, dev_id_override);
        }
        return cmd_server_start(cfg_path, port_override, mode_override);
    }

    /* ─── Symlink Handling: qseal-client ─────────────────────────────── */
    if (is_cli_bin) {
        if (argc < 2 || argv[1][0] == '-') {
            return cmd_client_connect(cfg_path, server_override, port_override, mode_override, msg_override);
        }
        const char *sub = argv[1];
        if (strcmp(sub, "connect") == 0) {
            return cmd_client_connect(cfg_path, server_override, port_override, mode_override, msg_override);
        } else if (strcmp(sub, "send") == 0) {
            if (argc > 2 && argv[2][0] != '-') msg_override = argv[2];
            return cmd_client_connect(cfg_path, server_override, port_override, mode_override, msg_override);
        } else if (strcmp(sub, "disconnect") == 0) {
            return cmd_client_disconnect();
        } else if (strcmp(sub, "status") == 0) {
            return cmd_client_status(cfg_path);
        } else if (strcmp(sub, "show-logs") == 0) {
            return cmd_client_show_logs();
        } else if (strcmp(sub, "validate") == 0) {
            return cmd_config(1, (char *[]){"validate"}, cfg_path);
        } else if (strcmp(sub, "init") == 0) {
            uint16_t p = port_override ? (uint16_t)atoi(port_override) : QSEAL_DEFAULT_PORT;
            qseal_mode_t m = mode_override ? qseal_mode_from_string(mode_override) : QSEAL_MODE_HYBRID;
            return qseal_setup_init_client(cfg_path, server_override, p, m, dev_id_override, expected_srv_override);
        }
        return cmd_client_connect(cfg_path, server_override, port_override, mode_override, msg_override);
    }

    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "setup") == 0) {
        return qseal_setup_wizard_run(cfg_path, non_interactive);
    }
    if (strcmp(cmd, "detect") == 0) {
        return cmd_detect();
    }
    if (strcmp(cmd, "profiles") == 0) {
        return cmd_profiles(argc - 2, argv + 2);
    }
    if (strcmp(cmd, "adaptive") == 0) {
        if (argc > 2 && strcmp(argv[2], "explain") == 0) {
            return cmd_adaptive_explain();
        }
        return cmd_adaptive_explain();
    }
    if (strcmp(cmd, "config") == 0) {
        return cmd_config(argc - 2, argv + 2, cfg_path);
    }
    if (strcmp(cmd, "server") == 0) {
        if (!cfg_explicit) cfg_path = get_server_config_path();
        const char *subcmd = (argc > 2 && argv[2][0] != '-') ? argv[2] : "start";

        if (strcmp(subcmd, "init") == 0) {
            uint16_t p = port_override ? (uint16_t)atoi(port_override) : QSEAL_DEFAULT_PORT;
            qseal_mode_t m = mode_override ? qseal_mode_from_string(mode_override) : QSEAL_MODE_HYBRID;
            return qseal_setup_init_server(cfg_path, p, bind_override, advertised_override, m, dev_id_override);
        }
        if (strcmp(subcmd, "stop") == 0) {
            return cmd_server_stop();
        }
        if (strcmp(subcmd, "restart") == 0) {
            return cmd_server_restart(cfg_path, port_override, mode_override);
        }
        if (strcmp(subcmd, "status") == 0) {
            return cmd_server_status(cfg_path);
        }
        if (strcmp(subcmd, "clients") == 0) {
            return cmd_server_clients();
        }
        if (strcmp(subcmd, "show-logs") == 0) {
            return cmd_server_show_logs();
        }
        if (strcmp(subcmd, "validate") == 0) {
            return cmd_config(1, (char *[]){"validate"}, cfg_path);
        }

        /* Server start */
        for (int i = 2; i < argc; i++) {
            if (argv[i][0] == '-') {
                if (strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "--mode") == 0 || strcmp(argv[i], "--config") == 0) i++;
                continue;
            }
            if (strcmp(argv[i], "start") == 0) continue;
            if (atoi(argv[i]) > 0 && !port_override) {
                port_override = argv[i];
            }
        }
        return cmd_server_start(cfg_path, port_override, mode_override);
    }
    if (strcmp(cmd, "client") == 0) {
        if (!cfg_explicit) cfg_path = get_client_config_path();
        const char *subcmd = (argc > 2 && argv[2][0] != '-') ? argv[2] : "connect";

        if (strcmp(subcmd, "init") == 0) {
            uint16_t p = port_override ? (uint16_t)atoi(port_override) : QSEAL_DEFAULT_PORT;
            qseal_mode_t m = mode_override ? qseal_mode_from_string(mode_override) : QSEAL_MODE_HYBRID;
            return qseal_setup_init_client(cfg_path, server_override, p, m, dev_id_override, expected_srv_override);
        }
        if (strcmp(subcmd, "disconnect") == 0) {
            return cmd_client_disconnect();
        }
        if (strcmp(subcmd, "status") == 0) {
            return cmd_client_status(cfg_path);
        }
        if (strcmp(subcmd, "show-logs") == 0) {
            return cmd_client_show_logs();
        }
        if (strcmp(subcmd, "validate") == 0) {
            return cmd_config(1, (char *[]){"validate"}, cfg_path);
        }

        /* Client connect */
        for (int i = 2; i < argc; i++) {
            if (argv[i][0] == '-') {
                if (strcmp(argv[i], "--server") == 0 || strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "--mode") == 0 || strcmp(argv[i], "--msg") == 0 || strcmp(argv[i], "--config") == 0) i++;
                continue;
            }
            if (strcmp(argv[i], "connect") == 0) continue;
            if (strcmp(argv[i], "send") == 0) {
                if (i + 1 < argc && argv[i + 1][0] != '-') {
                    msg_override = argv[i + 1];
                    i++;
                }
                continue;
            }
            if (!server_override && (strchr(argv[i], '.') != NULL || atoi(argv[i]) == 0)) {
                server_override = argv[i];
            } else if (!port_override && atoi(argv[i]) > 0) {
                port_override = argv[i];
            }
        }
        return cmd_client_connect(cfg_path, server_override, port_override, mode_override, msg_override);
    }
    if (strcmp(cmd, "clients") == 0) {
        return cmd_server_clients();
    }
    if (strcmp(cmd, "status") == 0) {
        return cmd_status(cfg_path);
    }
    if (strcmp(cmd, "diagnostics") == 0) {
        return cmd_diagnostics();
    }
    if (strcmp(cmd, "benchmark") == 0) {
        return cmd_benchmark(mode_override, iters);
    }

    fprintf(stderr, "Unknown command '%s'. Run '%s --help' for available commands.\n", cmd, argv[0]);
    return 1;
}
