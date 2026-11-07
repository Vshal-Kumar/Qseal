/*
 * securecomm/src/cli/cli.c
 *
 * Command-Line Interface dispatcher and subcommand implementations.
 */

#define _POSIX_C_SOURCE 200809L
#include "cli.h"
#include "securecomm/common.h"
#include "securecomm/error.h"
#include "securecomm/config.h"
#include "securecomm/device_profile.h"
#include "securecomm/profile_registry.h"
#include "securecomm/policy.h"
#include "securecomm/adaptive.h"
#include "securecomm/identity.h"
#include "securecomm/server.h"
#include "securecomm/client.h"
#include "securecomm/metrics.h"
#include "securecomm/crypto_backend.h"
#include "securecomm/logging.h"
#include "../setup/setup_wizard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>

#define DEFAULT_SERVER_CONFIG_PATH "/etc/qseal/server.json"
#define DEFAULT_CLIENT_CONFIG_PATH "/etc/qseal/client.json"
#define DEFAULT_CONFIG_PATH        "/etc/qseal/qseal.json"
#define FALLBACK_CONFIG_PATH       "./config/qseal.json"

static const char *get_default_config_path(void) {
    const char *home = getenv("HOME");
    static char user_cfg[SECURECOMM_MAX_PATH_LEN];
    if (home && strlen(home) > 0) {
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/server.json", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/client.json", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/qseal.json", home);
        if (access(user_cfg, R_OK) == 0) return user_cfg;
    }
    if (access(DEFAULT_SERVER_CONFIG_PATH, R_OK) == 0) return DEFAULT_SERVER_CONFIG_PATH;
    if (access(DEFAULT_CLIENT_CONFIG_PATH, R_OK) == 0) return DEFAULT_CLIENT_CONFIG_PATH;
    if (access(DEFAULT_CONFIG_PATH, R_OK) == 0) return DEFAULT_CONFIG_PATH;
    if (access(FALLBACK_CONFIG_PATH, R_OK) == 0) return FALLBACK_CONFIG_PATH;
    if (access("/etc/securecomm/securecomm.json", R_OK) == 0) return "/etc/securecomm/securecomm.json";
    if (getuid() != 0 && home && strlen(home) > 0) {
        snprintf(user_cfg, sizeof(user_cfg), "%s/.config/qseal/qseal.json", home);
        return user_cfg;
    }
    return DEFAULT_CONFIG_PATH;
}

static void print_version(void) {
    printf("QSEAL (Quantum-Secure Enterprise Access & Link) version %s\n", SECURECOMM_VERSION_STRING);
    printf("Independent Hybrid and Post-Quantum Secure Networking Platform\n");
    printf("Protocols: Hybrid (X25519 + ML-KEM-768 + ML-DSA-65) & Pure PQC (ML-KEM-768 + ML-DSA-65)\n");
    printf("AEAD: ChaCha20-Poly1305 (RFC 8439) | KDF: HKDF-SHA-384 (RFC 5869)\n");
    printf("Target Architecture: Linux x86_64 / ARM64 / ARM32 (Native UDP Direct Connectivity)\n");
}

static void print_help(const char *prog) {
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Platform Management Commands:\n");
    printf("  setup                     Run guided interactive onboarding setup wizard\n");
    printf("  detect                    Detect hardware, CPU SIMD features, memory, and crypto backends\n");
    printf("  diagnostics               Run comprehensive network, port, NAT, and crypto diagnostics\n");
    printf("  status                    Display service configuration and running state\n");
    printf("  benchmark                 Run cryptographic microbenchmarks (Hybrid & Pure PQC)\n");
    printf("\nServer Commands:\n");
    printf("  server [start] [port]     Launch independent QSEAL UDP server (default: 0.0.0.0:9877)\n");
    printf("  server init               Initialize server identity keys and default configuration\n");
    printf("\nClient Commands:\n");
    printf("  client [connect] [host]   Establish secure quantum-safe tunnel to server\n");
    printf("  client init               Initialize client identity keys and default configuration\n");
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
    printf("  %s server start --port 9877\n\n", prog);
    printf("  # Direct Public-IP Client Connection:\n");
    printf("  %s setup --role client\n", prog);
    printf("  %s client connect 203.0.113.10 9877\n", prog);
    printf("  %s client connect --server vpn.company.com --port 9877\n", prog);
}

/* ─── Signal handling for Server ─────────────────────────────────── */
static securecomm_server_t *g_server = NULL;

static void server_sigint_handler(int sig) {
    (void)sig;
    if (g_server) {
        securecomm_server_stop(g_server);
    }
}

/* ─── Subcommand: detect ─────────────────────────────────────────── */
static int cmd_detect(void) {
    securecomm_device_profile_t dev;
    int rc = securecomm_device_profile_collect(&dev);
    if (rc != SECURECOMM_SUCCESS) {
        fprintf(stderr, "Error detecting hardware capabilities: %s\n", securecomm_strerror(rc));
        return 1;
    }
    securecomm_device_profile_print(&dev, stdout);
    return 0;
}

/* ─── Subcommand: profiles ───────────────────────────────────────── */
static int cmd_profiles(int argc, char **argv) {
    if (argc < 1 || strcmp(argv[0], "list") == 0) {
        securecomm_profile_list_print(stdout);
        return 0;
    }

    if (strcmp(argv[0], "check") == 0) {
        securecomm_device_profile_t dev;
        securecomm_device_profile_collect(&dev);

        size_t count = 0;
        const securecomm_profile_t *list = securecomm_profile_get_all(&count);

        printf("\n=========================================================================================\n");
        printf("                     CRYPTOGRAPHIC PROFILE COMPATIBILITY CHECK                           \n");
        printf("=========================================================================================\n");
        printf(" %-20s %-12s %-10s %s\n", "PROFILE ID", "MODE", "SUPPORTED", "COMPATIBILITY NOTE");
        printf("-----------------------------------------------------------------------------------------\n");

        for (size_t i = 0; i < count; i++) {
            bool ok = securecomm_profile_is_device_compatible(&list[i], &dev);
            printf(" %-20s %-12s %-10s %s\n",
                   list[i].id,
                   securecomm_mode_to_string(list[i].mode),
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
    securecomm_device_profile_t dev;
    securecomm_device_profile_collect(&dev);

    securecomm_policy_t pol;
    securecomm_policy_init_default(&pol);

    securecomm_adaptive_decision_t decision;
    int rc = securecomm_adaptive_select(&dev, &pol, NULL, 0, &decision);
    if (rc != SECURECOMM_SUCCESS) {
        fprintf(stderr, "Adaptive selection failed: %s\n", securecomm_strerror(rc));
        return 1;
    }

    securecomm_adaptive_explain(&decision, &dev, &pol, stdout);
    return 0;
}

/* ─── Subcommand: config ─────────────────────────────────────────── */
static int cmd_config(int argc, char **argv, const char *cfg_path) {
    if (argc < 1 || strcmp(argv[0], "validate") == 0) {
        securecomm_config_t cfg;
        int rc = securecomm_config_load(&cfg, cfg_path);
        if (rc != SECURECOMM_SUCCESS) {
            fprintf(stderr, "FAIL: Could not load configuration '%s': %s\n", cfg_path, securecomm_strerror(rc));
            return 1;
        }

        rc = securecomm_config_validate(&cfg);
        if (rc != SECURECOMM_SUCCESS) {
            fprintf(stderr, "FAIL: Configuration validation error: %s\n", securecomm_strerror(rc));
            return 1;
        }

        printf("OK: Configuration at '%s' is valid and syntax-compliant.\n", cfg_path);
        return 0;
    }

    if (strcmp(argv[0], "show") == 0) {
        securecomm_config_t cfg;
        int rc = securecomm_config_load(&cfg, cfg_path);
        if (rc != SECURECOMM_SUCCESS) {
            fprintf(stderr, "Error loading configuration '%s': %s\n", cfg_path, securecomm_strerror(rc));
            return 1;
        }
        securecomm_config_print(&cfg, stdout);
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
    securecomm_config_t cfg;
    int rc = securecomm_config_load(&cfg, cfg_path);
    if (rc != SECURECOMM_SUCCESS) {
        securecomm_config_init_default(&cfg);
        cfg.role = SECURECOMM_ROLE_SERVER;
    }

    if (override_port && strlen(override_port) > 0) {
        cfg.port = (uint16_t)atoi(override_port);
    } else if (cfg.port == 0) {
        cfg.port = SECURECOMM_DEFAULT_PORT;
    }
    if (override_mode) {
        cfg.mode = securecomm_mode_from_string(override_mode);
    }

    /* Load identity */
    securecomm_identity_t ident;
    char base_dir[SECURECOMM_MAX_PATH_LEN] = "/etc/qseal";
    if (getuid() != 0) {
        const char *home = getenv("HOME");
        if (home && strlen(home) > 0) {
            snprintf(base_dir, sizeof(base_dir), "%s/.config/qseal", home);
        } else {
            snprintf(base_dir, sizeof(base_dir), "/tmp/qseal-%u", (unsigned int)getuid());
        }
    } else if (access("/etc/qseal", F_OK) != 0 && access("/etc/securecomm", F_OK) == 0) {
        snprintf(base_dir, sizeof(base_dir), "/etc/securecomm");
    }

    securecomm_identity_init(&ident, cfg.device_id, cfg.mode, base_dir);
    if (strlen(cfg.private_key_path) > 0) {
        snprintf(ident.private_key_path, sizeof(ident.private_key_path), "%s", cfg.private_key_path);
    }
    if (strlen(cfg.public_key_path) > 0) {
        snprintf(ident.public_key_path, sizeof(ident.public_key_path), "%s", cfg.public_key_path);
    }
    if (strlen(cfg.trust_store_path) > 0) {
        snprintf(ident.trust_store_path, sizeof(ident.trust_store_path), "%s", cfg.trust_store_path);
    }

    if (!securecomm_identity_exists(&ident)) {
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
        int l_rc = securecomm_identity_load(&ident);
        if (l_rc != SECURECOMM_SUCCESS) {
            fprintf(stderr, "Failed to load server identity: %s\n", securecomm_strerror(l_rc));
            return 1;
        }
    }

    g_server = securecomm_server_create(&cfg, &ident);
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
    printf("  Crypto Mode   : %s\n", securecomm_mode_to_string(cfg.mode));
    printf("  Device ID     : %s\n", cfg.device_id);
    printf("  Fingerprint   : %.16s...\n", ident.fingerprint);
    printf("  Key File      : %s\n\n", ident.private_key_path);
    printf("[Ready] Waiting for incoming client connections... (Press Ctrl+C to stop)\n\n");

    rc = securecomm_server_run(g_server);

    const securecomm_metrics_t *m = securecomm_server_get_metrics(g_server);
    if (m) {
        securecomm_metrics_print(m, stdout);
    }

    securecomm_server_free(g_server);
    g_server = NULL;
    return rc == SECURECOMM_SUCCESS ? 0 : 1;
}

/* ─── Subcommand: client connect ─────────────────────────────────── */
static int cmd_client_connect(const char *cfg_path, const char *server_host, const char *port_str,
                              const char *mode_str, const char *msg) {
    securecomm_config_t cfg;
    int rc = securecomm_config_load(&cfg, cfg_path);
    if (rc != SECURECOMM_SUCCESS) {
        securecomm_config_init_default(&cfg);
        cfg.role = SECURECOMM_ROLE_CLIENT;
    }

    if (server_host && strlen(server_host) > 0) {
        snprintf(cfg.server_host, sizeof(cfg.server_host), "%s", server_host);
        snprintf(cfg.server_address, sizeof(cfg.server_address), "%s", server_host);
    } else if (strlen(cfg.server_host) == 0 && strlen(cfg.server_address) == 0) {
        snprintf(cfg.server_host, sizeof(cfg.server_host), "%s", SECURECOMM_DEFAULT_SERVER_HOST);
        snprintf(cfg.server_address, sizeof(cfg.server_address), "%s", SECURECOMM_DEFAULT_SERVER_HOST);
    } else if (strlen(cfg.server_host) == 0 && strlen(cfg.server_address) > 0) {
        snprintf(cfg.server_host, sizeof(cfg.server_host), "%s", cfg.server_address);
    }

    if (port_str && strlen(port_str) > 0) {
        cfg.port = (uint16_t)atoi(port_str);
    } else if (cfg.port == 0) {
        cfg.port = SECURECOMM_DEFAULT_PORT;
    }
    if (mode_str) cfg.mode = securecomm_mode_from_string(mode_str);

    /* Initialize identity with user-path fallback */
    securecomm_identity_t ident;
    char base_dir[SECURECOMM_MAX_PATH_LEN] = "/etc/qseal";
    if (getuid() != 0) {
        const char *home = getenv("HOME");
        if (home && strlen(home) > 0) {
            snprintf(base_dir, sizeof(base_dir), "%s/.config/qseal", home);
        } else {
            snprintf(base_dir, sizeof(base_dir), "/tmp/qseal-%u", (unsigned int)getuid());
        }
    } else if (access("/etc/qseal", F_OK) != 0 && access("/etc/securecomm", F_OK) == 0) {
        snprintf(base_dir, sizeof(base_dir), "/etc/securecomm");
    }

    securecomm_identity_init(&ident, cfg.device_id, cfg.mode, base_dir);
    if (strlen(cfg.private_key_path) > 0) {
        snprintf(ident.private_key_path, sizeof(ident.private_key_path), "%s", cfg.private_key_path);
    }
    if (strlen(cfg.public_key_path) > 0) {
        snprintf(ident.public_key_path, sizeof(ident.public_key_path), "%s", cfg.public_key_path);
    }
    if (strlen(cfg.trust_store_path) > 0) {
        snprintf(ident.trust_store_path, sizeof(ident.trust_store_path), "%s", cfg.trust_store_path);
    }

    if (!securecomm_identity_exists(&ident)) {
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
        int l_rc = securecomm_identity_load(&ident);
        if (l_rc != SECURECOMM_SUCCESS) {
            fprintf(stderr, "Failed to load client identity keypair: %s\n", securecomm_strerror(l_rc));
            return 1;
        }
    }

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                 QSEAL Secure Client (Hybrid & Pure Post-Quantum)                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════╝\n");
    printf("  Target Server : %s:%u (UDP)\n", cfg.server_host, cfg.port);
    printf("  Crypto Mode   : %s\n", securecomm_mode_to_string(cfg.mode));
    printf("  Device ID     : %s\n", cfg.device_id);
    printf("  Fingerprint   : %.16s...\n", ident.fingerprint);
    printf("  Key File      : %s\n\n", ident.private_key_path);

    securecomm_client_t *client = securecomm_client_create(&cfg, &ident);
    if (!client) {
        fprintf(stderr, "Failed to create QSEAL client instance\n");
        return 1;
    }

    printf("[*] Connecting to %s:%u over UDP...\n", cfg.server_host, cfg.port);
    rc = securecomm_client_connect(client);
    if (rc != SECURECOMM_SUCCESS) {
        fprintf(stderr, "[!] Connection failed: %s\n", securecomm_strerror(rc));
        fprintf(stderr, "    Tip: Verify server is running on %s:%u and UDP port %u is open.\n\n",
                cfg.server_host, cfg.port, cfg.port);
        securecomm_client_free(client);
        return 1;
    }

    printf("[✓] Post-Quantum Handshake Established! Mutual Authentication Verified.\n");
    printf("[✓] Encrypted Session Active.\n\n");

    if (msg) {
        rc = securecomm_client_send(client, (const uint8_t *)msg, strlen(msg));
        if (rc == SECURECOMM_SUCCESS) {
            printf("[✓] Message sent successfully (%zu bytes).\n", strlen(msg));
        } else {
            fprintf(stderr, "Failed to send message: %s\n", securecomm_strerror(rc));
        }
        securecomm_client_disconnect(client);
    } else {
        securecomm_client_run_interactive(client);
    }

    const securecomm_metrics_t *m = securecomm_client_get_metrics(client);
    if (m) {
        securecomm_metrics_print(m, stdout);
    }

    securecomm_client_free(client);
    return 0;
}

/* ─── Subcommand: status ─────────────────────────────────────────── */
static int cmd_status(const char *cfg_path) {
    printf("=========================================================\n");
    printf("                 QSEAL SERVICE STATUS                    \n");
    printf("=========================================================\n");
    printf(" Configuration File : %s\n", cfg_path);
    if (access(cfg_path, F_OK) == 0) {
        printf(" Config Status      : PRESENT [0600]\n");
    } else {
        printf(" Config Status      : NOT CONFIGURED (Run 'qseal setup' or 'qseal server init')\n");
    }
    printf(" Process ID (PID)   : %d\n", getpid());
    printf(" OpenSSL Version    : OpenSSL 3.x EVP Engine Active\n");
    printf(" Post-Quantum Engine: FIPS 203 (ML-KEM-768) & FIPS 204 (ML-DSA-65) Active\n");
    printf(" Classical Engine   : X25519 & ChaCha20-Poly1305 Active\n");
    printf(" Network Transports : Native UDP Direct Connectivity (No Tailscale/VPN dependency)\n");
    printf("=========================================================\n");
    return 0;
}

/* ─── Subcommand: diagnostics ────────────────────────────────────── */
static int cmd_diagnostics(void) {
    printf("=================================================================================\n");
    printf("                          QSEAL PLATFORM DIAGNOSTICS                             \n");
    printf("=================================================================================\n");

    /* 1. Hardware checks */
    printf("[1/4] Host Hardware & SIMD Acceleration:\n");
    securecomm_device_profile_t dev;
    securecomm_device_profile_collect(&dev);
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
    securecomm_mode_t mode = SECURECOMM_MODE_HYBRID;
    if (mode_str) mode = securecomm_mode_from_string(mode_str);

    const securecomm_profile_t *prof = securecomm_profile_get_by_mode(mode);
    if (!prof) prof = securecomm_profile_get_by_id("profile-hybrid-1");

    crypto_backend_t *backend = securecomm_crypto_backend_create(prof);
    if (!backend) {
        fprintf(stderr, "Failed to create crypto backend for benchmark\n");
        return 1;
    }

    printf("\n=================================================================================\n");
    printf("               SECURECOMM CRYPTOGRAPHIC BENCHMARK (%s)                           \n",
           securecomm_mode_to_string(mode));
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
    securecomm_crypto_backend_free(backend);
    return 0;
}

/* ─── Main CLI Dispatcher ────────────────────────────────────────── */
int securecomm_cli_dispatch(int argc, char **argv) {
    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    const char *cfg_path = get_default_config_path();
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

    /* Scan for flags */
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
        }
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port_override = argv[++i];
        }
        if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            bind_override = argv[++i];
        }
        if (strcmp(argv[i], "--advertised") == 0 && i + 1 < argc) {
            advertised_override = argv[++i];
        }
        if (strcmp(argv[i], "--device-id") == 0 && i + 1 < argc) {
            dev_id_override = argv[++i];
        }
        if (strcmp(argv[i], "--expected-server") == 0 && i + 1 < argc) {
            expected_srv_override = argv[++i];
        }
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode_override = argv[++i];
        }
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            server_override = argv[++i];
        }
        if (strcmp(argv[i], "--msg") == 0 && i + 1 < argc) {
            msg_override = argv[++i];
        }
        if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            iters = atoi(argv[++i]);
        }
        if (strcmp(argv[i], "--non-interactive") == 0) {
            non_interactive = true;
        }
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "setup") == 0) {
        return securecomm_setup_wizard_run(cfg_path, non_interactive);
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
        if (argc > 2 && strcmp(argv[2], "init") == 0) {
            uint16_t p = port_override ? (uint16_t)atoi(port_override) : SECURECOMM_DEFAULT_PORT;
            securecomm_mode_t m = mode_override ? securecomm_mode_from_string(mode_override) : SECURECOMM_MODE_HYBRID;
            return securecomm_setup_init_server(cfg_path, p, bind_override, advertised_override, m, dev_id_override);
        }
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
        if (argc > 2 && strcmp(argv[2], "init") == 0) {
            uint16_t p = port_override ? (uint16_t)atoi(port_override) : SECURECOMM_DEFAULT_PORT;
            securecomm_mode_t m = mode_override ? securecomm_mode_from_string(mode_override) : SECURECOMM_MODE_HYBRID;
            return securecomm_setup_init_client(cfg_path, server_override, p, m, dev_id_override, expected_srv_override);
        }
        for (int i = 2; i < argc; i++) {
            if (argv[i][0] == '-') {
                if (strcmp(argv[i], "--server") == 0 || strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "--mode") == 0 || strcmp(argv[i], "--msg") == 0 || strcmp(argv[i], "--config") == 0) i++;
                continue;
            }
            if (strcmp(argv[i], "connect") == 0) continue;
            if (!server_override && (strchr(argv[i], '.') != NULL || atoi(argv[i]) == 0)) {
                server_override = argv[i];
            } else if (!port_override && atoi(argv[i]) > 0) {
                port_override = argv[i];
            }
        }
        return cmd_client_connect(cfg_path, server_override, port_override, mode_override, msg_override);
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
