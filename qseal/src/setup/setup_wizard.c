/*
 * qseal/src/setup/setup_wizard.c
 *
 * Interactive and automated Setup Wizard for QSEAL.
 * Configures, provisions, validates, and tests Server and Client nodes.
 */

#define _POSIX_C_SOURCE 200809L
#include "setup_wizard.h"
#include "qseal/device_profile.h"
#include "qseal/profile_registry.h"
#include "qseal/identity.h"
#include "qseal/error.h"
#include "qseal/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>

static void ensure_dir_exists(const char *dir) {
    if (!dir || strlen(dir) == 0) return;
    char tmp[QSEAL_MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp);
    for (size_t i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            mkdir(tmp, 0700);
            tmp[i] = '/';
        }
    }
    mkdir(tmp, 0700);
}

static void read_input(const char *prompt, const char *def_val, char *out, size_t out_sz, bool non_interactive) {
    if (non_interactive || !isatty(STDIN_FILENO)) {
        snprintf(out, out_sz, "%s", def_val);
        printf("%s [%s]: %s\n", prompt, def_val, def_val);
        return;
    }

    printf("%s [%s]: ", prompt, def_val);
    fflush(stdout);

    char buf[512];
    if (fgets(buf, sizeof(buf), stdin)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
            len--;
        }
        if (len > 0) {
            snprintf(out, out_sz, "%s", buf);
            return;
        }
    }
    snprintf(out, out_sz, "%s", def_val);
}

static bool test_port_bindable(const char *bind_addr, uint16_t port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return false;

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (!bind_addr || strcmp(bind_addr, "0.0.0.0") == 0 || strlen(bind_addr) == 0) {
        sin.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, bind_addr, &sin.sin_addr);
    }

    int rc = bind(s, (struct sockaddr *)&sin, sizeof(sin));
    close(s);
    return (rc == 0);
}

int qseal_setup_init_server(const char *config_path,
                                 uint16_t port,
                                 const char *bind_addr,
                                 const char *adv_endpoint,
                                 qseal_mode_t mode,
                                 const char *device_id) {
    char resolved_path[QSEAL_MAX_PATH_LEN];
    char base_dir[QSEAL_MAX_PATH_LEN];

    if (config_path && strlen(config_path) > 0) {
        snprintf(resolved_path, sizeof(resolved_path), "%s", config_path);
    } else {
        if (getuid() == 0) {
            snprintf(resolved_path, sizeof(resolved_path), "/etc/qseal/server.yaml");
        } else {
            const char *home = getenv("HOME");
            snprintf(resolved_path, sizeof(resolved_path), "%s/.config/qseal/server.yaml", home ? home : "/tmp");
        }
    }

    /* Extract directory */
    snprintf(base_dir, sizeof(base_dir), "%s", resolved_path);
    char *slash = strrchr(base_dir, '/');
    if (slash) *slash = '\0';
    ensure_dir_exists(base_dir);

    qseal_config_t cfg;
    qseal_config_init_default(&cfg);
    cfg.role = QSEAL_ROLE_SERVER;
    cfg.port = (port > 0) ? port : QSEAL_DEFAULT_PORT;
    cfg.mode = (mode == QSEAL_MODE_PQC) ? QSEAL_MODE_PQC : QSEAL_MODE_HYBRID;

    if (bind_addr && strlen(bind_addr) > 0) {
        snprintf(cfg.bind_address, sizeof(cfg.bind_address), "%s", bind_addr);
    } else {
        snprintf(cfg.bind_address, sizeof(cfg.bind_address), "0.0.0.0");
    }

    if (adv_endpoint && strlen(adv_endpoint) > 0) {
        snprintf(cfg.advertised_endpoint, sizeof(cfg.advertised_endpoint), "%s", adv_endpoint);
    }

    if (device_id && strlen(device_id) > 0) {
        snprintf(cfg.device_id, sizeof(cfg.device_id), "%s", device_id);
    } else {
        gethostname(cfg.device_id, sizeof(cfg.device_id));
        if (strlen(cfg.device_id) == 0) snprintf(cfg.device_id, sizeof(cfg.device_id), "qseal-server-1");
    }

    snprintf(cfg.private_key_path, sizeof(cfg.private_key_path), "%s/%s.key", base_dir, cfg.device_id);
    snprintf(cfg.public_key_path, sizeof(cfg.public_key_path), "%s/%s.pub", base_dir, cfg.device_id);
    snprintf(cfg.trust_store_path, sizeof(cfg.trust_store_path), "%s/trust_store.txt", base_dir);
    cfg.allow_client_to_client = true;
    cfg.allow_tofu = true;
    cfg.heartbeat_interval_sec = 15;
    cfg.session_timeout_sec = 60;

    /* Provision identity */
    qseal_identity_t ident;
    qseal_identity_init(&ident, cfg.device_id, cfg.mode, base_dir);
    snprintf(ident.private_key_path, sizeof(ident.private_key_path), "%s", cfg.private_key_path);
    snprintf(ident.public_key_path, sizeof(ident.public_key_path), "%s", cfg.public_key_path);
    snprintf(ident.trust_store_path, sizeof(ident.trust_store_path), "%s", cfg.trust_store_path);

    if (!qseal_identity_exists(&ident)) {
        int g_rc = qseal_identity_generate(&ident);
        if (g_rc != QSEAL_SUCCESS) {
            fprintf(stderr, "Error generating server identity: %s\n", qseal_strerror(g_rc));
            return g_rc;
        }
    } else {
        qseal_identity_load(&ident);
    }

    int s_rc = qseal_config_save_atomic(&cfg, resolved_path);
    if (s_rc != QSEAL_SUCCESS) {
        fprintf(stderr, "Error saving server configuration: %s\n", qseal_strerror(s_rc));
        return s_rc;
    }

    printf("[✓] QSEAL Server initialized successfully!\n");
    printf("    Config file : %s\n", resolved_path);
    printf("    Private key : %s (Permissions: 0600)\n", cfg.private_key_path);
    printf("    Fingerprint : %s\n", ident.fingerprint);
    return QSEAL_SUCCESS;
}

int qseal_setup_init_client(const char *config_path,
                                 const char *server_host,
                                 uint16_t port,
                                 qseal_mode_t mode,
                                 const char *device_id,
                                 const char *expected_server_id) {
    char resolved_path[QSEAL_MAX_PATH_LEN];
    char base_dir[QSEAL_MAX_PATH_LEN];

    if (config_path && strlen(config_path) > 0) {
        snprintf(resolved_path, sizeof(resolved_path), "%s", config_path);
    } else {
        if (getuid() == 0) {
            snprintf(resolved_path, sizeof(resolved_path), "/etc/qseal/client.yaml");
        } else {
            const char *home = getenv("HOME");
            snprintf(resolved_path, sizeof(resolved_path), "%s/.config/qseal/client.yaml", home ? home : "/tmp");
        }
    }

    snprintf(base_dir, sizeof(base_dir), "%s", resolved_path);
    char *slash = strrchr(base_dir, '/');
    if (slash) *slash = '\0';
    ensure_dir_exists(base_dir);

    qseal_config_t cfg;
    qseal_config_init_default(&cfg);
    cfg.role = QSEAL_ROLE_CLIENT;
    cfg.port = (port > 0) ? port : QSEAL_DEFAULT_PORT;
    cfg.mode = (mode == QSEAL_MODE_PQC) ? QSEAL_MODE_PQC : QSEAL_MODE_HYBRID;

    if (server_host && strlen(server_host) > 0) {
        snprintf(cfg.server_host, sizeof(cfg.server_host), "%s", server_host);
        snprintf(cfg.server_address, sizeof(cfg.server_address), "%s", server_host);
    } else {
        snprintf(cfg.server_host, sizeof(cfg.server_host), "127.0.0.1");
        snprintf(cfg.server_address, sizeof(cfg.server_address), "127.0.0.1");
    }

    if (device_id && strlen(device_id) > 0) {
        snprintf(cfg.device_id, sizeof(cfg.device_id), "%s", device_id);
    } else {
        gethostname(cfg.device_id, sizeof(cfg.device_id));
        if (strlen(cfg.device_id) == 0) snprintf(cfg.device_id, sizeof(cfg.device_id), "qseal-client-1");
    }

    if (expected_server_id && strlen(expected_server_id) > 0) {
        snprintf(cfg.expected_server_id, sizeof(cfg.expected_server_id), "%s", expected_server_id);
    }

    snprintf(cfg.private_key_path, sizeof(cfg.private_key_path), "%s/%s.key", base_dir, cfg.device_id);
    snprintf(cfg.public_key_path, sizeof(cfg.public_key_path), "%s/%s.pub", base_dir, cfg.device_id);
    snprintf(cfg.trust_store_path, sizeof(cfg.trust_store_path), "%s/trust_store.txt", base_dir);
    cfg.allow_tofu = true;
    cfg.heartbeat_interval_sec = 15;
    cfg.session_timeout_sec = 60;

    qseal_identity_t ident;
    qseal_identity_init(&ident, cfg.device_id, cfg.mode, base_dir);
    snprintf(ident.private_key_path, sizeof(ident.private_key_path), "%s", cfg.private_key_path);
    snprintf(ident.public_key_path, sizeof(ident.public_key_path), "%s", cfg.public_key_path);
    snprintf(ident.trust_store_path, sizeof(ident.trust_store_path), "%s", cfg.trust_store_path);

    if (!qseal_identity_exists(&ident)) {
        int g_rc = qseal_identity_generate(&ident);
        if (g_rc != QSEAL_SUCCESS) {
            fprintf(stderr, "Error generating client identity: %s\n", qseal_strerror(g_rc));
            return g_rc;
        }
    } else {
        qseal_identity_load(&ident);
    }

    int s_rc = qseal_config_save_atomic(&cfg, resolved_path);
    if (s_rc != QSEAL_SUCCESS) {
        fprintf(stderr, "Error saving client configuration: %s\n", qseal_strerror(s_rc));
        return s_rc;
    }

    printf("[✓] QSEAL Client initialized successfully!\n");
    printf("    Config file : %s\n", resolved_path);
    printf("    Private key : %s (Permissions: 0600)\n", cfg.private_key_path);
    printf("    Fingerprint : %s\n", ident.fingerprint);
    return QSEAL_SUCCESS;
}

int qseal_setup_wizard_run(const char *config_path, bool non_interactive) {
    char resolved_config_path[QSEAL_MAX_PATH_LEN];

    bool custom_path = (config_path && strlen(config_path) > 0);
    if (custom_path) {
        snprintf(resolved_config_path, sizeof(resolved_config_path), "%s", config_path);
    }

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                    QSEAL SYSTEM ONBOARDING & SETUP WIZARD                        ║\n");
    printf("║           Quantum-Secure Enterprise Access & Link Networking Platform            ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════╝\n\n");

    /* ─── Step 1: Detect Device Environment ───────────────────────── */
    printf("[1/7] Detecting Host Hardware & Cryptographic Engine...\n");
    qseal_device_profile_t dev;
    qseal_device_profile_collect(&dev);
    qseal_device_profile_print(&dev, stdout);

    qseal_config_t cfg;
    qseal_config_init_default(&cfg);

    char ans[256];

    /* ─── Step 2: Role Selection ─────────────────────────────────── */
    printf("\n[2/7] Select Node Role:\n");
    printf("  1) Server  (Headless Daemon - listens for incoming authenticated tunnels)\n");
    printf("  2) Client  (Initiate post-quantum encrypted connection to server)\n");
    read_input("Select role (1 or 2)", "1", ans, sizeof(ans), non_interactive);
    if (ans[0] == '2' || strcasecmp(ans, "client") == 0) {
        cfg.role = QSEAL_ROLE_CLIENT;
        if (!custom_path) {
            if (getuid() == 0) {
                snprintf(resolved_config_path, sizeof(resolved_config_path), "/etc/qseal/client.yaml");
            } else {
                const char *home = getenv("HOME");
                snprintf(resolved_config_path, sizeof(resolved_config_path), "%s/.config/qseal/client.yaml", home ? home : "/tmp");
            }
        }
    } else {
        cfg.role = QSEAL_ROLE_SERVER;
        if (!custom_path) {
            if (getuid() == 0) {
                snprintf(resolved_config_path, sizeof(resolved_config_path), "/etc/qseal/server.yaml");
            } else {
                const char *home = getenv("HOME");
                snprintf(resolved_config_path, sizeof(resolved_config_path), "%s/.config/qseal/server.yaml", home ? home : "/tmp");
            }
        }
    }

    /* ─── Step 3: Cryptographic Profile ──────────────────────────── */
    printf("\n[3/7] Select Cryptographic Security Profile:\n");
    printf("  1) Hybrid Mode    : X25519 + ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305 [RECOMMENDED]\n");
    printf("  2) Pure PQC Mode  : ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305 [FIPS 203/204]\n");
    read_input("Select profile (1 or 2)", "1", ans, sizeof(ans), non_interactive);
    if (ans[0] == '2' || strcasecmp(ans, "pqc") == 0) {
        cfg.mode = QSEAL_MODE_PQC;
    } else {
        cfg.mode = QSEAL_MODE_HYBRID;
    }
    cfg.port = QSEAL_DEFAULT_PORT;

    /* ─── Step 4: Network & Public-IP Configuration ──────────────── */
    printf("\n[4/7] Network & Endpoint Configuration:\n");
    char port_str[32];
    snprintf(port_str, sizeof(port_str), "%u", cfg.port);

    if (cfg.role == QSEAL_ROLE_SERVER) {
        read_input("Local Bind Address (0.0.0.0 for all interfaces)", "0.0.0.0", cfg.bind_address, sizeof(cfg.bind_address), non_interactive);
        read_input("UDP Listening Port", port_str, ans, sizeof(ans), non_interactive);
        cfg.port = (uint16_t)atoi(ans);

        /* Pre-binding check */
        if (test_port_bindable(cfg.bind_address, cfg.port)) {
            printf("  [✓] Port verification: UDP %s:%u is available for binding.\n", cfg.bind_address, cfg.port);
        } else {
            printf("  [!] Port warning: UDP %s:%u appears to be in use or requires permissions.\n", cfg.bind_address, cfg.port);
        }

        read_input("Advertised Public Endpoint (e.g. 203.0.113.199:9877 or vpn.corp.com:9877)", "", cfg.advertised_endpoint, sizeof(cfg.advertised_endpoint), non_interactive);

        read_input("Allow Client-to-Client Routed Communication? (y/n)", "y", ans, sizeof(ans), non_interactive);
        cfg.allow_client_to_client = (ans[0] == 'y' || ans[0] == 'Y');

        printf("\n  [i] WAN / NAT Diagnostic Advice:\n");
        printf("      - If this server has a directly attached Public IP, clients connect directly.\n");
        printf("      - If behind a NAT router (e.g. 192.168.x.x / 10.x.x.x), configure UDP port-forwarding for port %u.\n", cfg.port);
        printf("      - If behind CGNAT (100.64.0.0/10), inbound connections cannot be established without a public IP.\n");
    } else {
        read_input("Remote Server Public IP or DNS Hostname", "127.0.0.1", cfg.server_host, sizeof(cfg.server_host), non_interactive);
        snprintf(cfg.server_address, sizeof(cfg.server_address), "%s", cfg.server_host);

        read_input("Remote Server UDP Port", port_str, ans, sizeof(ans), non_interactive);
        cfg.port = (uint16_t)atoi(ans);

        read_input("Expected Server Identity Fingerprint (Optional)", "", cfg.expected_server_id, sizeof(cfg.expected_server_id), non_interactive);
    }

    /* ─── Step 5: Identity & Key Provisioning ─────────────────────── */
    printf("\n[5/7] Identity & Cryptographic Key Paths:\n");
    char def_dev_id[64] = "qseal-node-1";
    char hbuf[64];
    if (gethostname(hbuf, sizeof(hbuf)) == 0 && strlen(hbuf) > 0) {
        snprintf(def_dev_id, sizeof(def_dev_id), "%s", hbuf);
    }
    read_input("Node Identifier", def_dev_id, cfg.device_id, sizeof(cfg.device_id), non_interactive);

    char base_dir[QSEAL_MAX_PATH_LEN];
    snprintf(base_dir, sizeof(base_dir), "%s", resolved_config_path);
    char *slash = strrchr(base_dir, '/');
    if (slash) *slash = '\0';
    ensure_dir_exists(base_dir);

    snprintf(cfg.private_key_path, sizeof(cfg.private_key_path), "%s/%s.key", base_dir, cfg.device_id);
    snprintf(cfg.public_key_path, sizeof(cfg.public_key_path), "%s/%s.pub", base_dir, cfg.device_id);
    snprintf(cfg.trust_store_path, sizeof(cfg.trust_store_path), "%s/trust_store.txt", base_dir);

    read_input("Private Key Path", cfg.private_key_path, ans, sizeof(ans), non_interactive);
    snprintf(cfg.private_key_path, sizeof(cfg.private_key_path), "%s", ans);

    read_input("Public Key Path", cfg.public_key_path, ans, sizeof(ans), non_interactive);
    snprintf(cfg.public_key_path, sizeof(cfg.public_key_path), "%s", ans);

    read_input("Trust Store Path", cfg.trust_store_path, ans, sizeof(ans), non_interactive);
    snprintf(cfg.trust_store_path, sizeof(cfg.trust_store_path), "%s", ans);

    read_input("Enable Trust On First Use (TOFU) for unpinned peers? (y/n)", "y", ans, sizeof(ans), non_interactive);
    cfg.allow_tofu = (ans[0] == 'y' || ans[0] == 'Y');
    cfg.heartbeat_interval_sec = 15;
    cfg.session_timeout_sec = 60;

    /* ─── Step 6: Review & Confirmation ──────────────────────────── */
    printf("\n[6/7] Proposed QSEAL Configuration Summary:\n");
    printf("─────────────────────────────────────────────────────────────────\n");
    printf(" Node Role          : %s\n", qseal_role_to_string(cfg.role));
    printf(" Crypto Profile     : %s\n", qseal_mode_to_string(cfg.mode));
    if (cfg.role == QSEAL_ROLE_SERVER) {
        printf(" Local Bind Address : %s:%u (UDP)\n", cfg.bind_address, cfg.port);
        printf(" Advertised Endpoint: %s\n", cfg.advertised_endpoint[0] ? cfg.advertised_endpoint : "(Same as bind address)");
        printf(" Client-to-Client   : %s\n", cfg.allow_client_to_client ? "Enabled" : "Disabled");
    } else {
        printf(" Target Server      : %s:%u (UDP)\n", cfg.server_host, cfg.port);
        if (cfg.expected_server_id[0]) {
            printf(" Expected Server ID : %s\n", cfg.expected_server_id);
        }
    }
    printf(" Node Identifier    : %s\n", cfg.device_id);
    printf(" Private Key        : %s (Permissions: 0600)\n", cfg.private_key_path);
    printf(" Public Key         : %s\n", cfg.public_key_path);
    printf(" Target Config File : %s\n", resolved_config_path);
    printf("─────────────────────────────────────────────────────────────────\n");

    read_input("Commit configuration and generate cryptographic keys? (y/n)", "y", ans, sizeof(ans), non_interactive);
    if (ans[0] != 'y' && ans[0] != 'Y') {
        printf("Setup aborted.\n");
        return QSEAL_SUCCESS;
    }

    /* ─── Step 7: Identity Generation & Atomic Write ─────────────── */
    printf("\n[7/7] Generating Cryptographic Identity & Saving Configuration...\n");

    qseal_identity_t ident;
    qseal_identity_init(&ident, cfg.device_id, cfg.mode, base_dir);
    snprintf(ident.private_key_path, sizeof(ident.private_key_path), "%s", cfg.private_key_path);
    snprintf(ident.public_key_path, sizeof(ident.public_key_path), "%s", cfg.public_key_path);
    snprintf(ident.trust_store_path, sizeof(ident.trust_store_path), "%s", cfg.trust_store_path);

    if (!qseal_identity_exists(&ident)) {
        printf("Generating cryptographic identity (%s)...\n", qseal_mode_to_string(cfg.mode));
        int g_rc = qseal_identity_generate(&ident);
        if (g_rc != QSEAL_SUCCESS) {
            fprintf(stderr, "Error generating identity keypair: %s\n", qseal_strerror(g_rc));
            return g_rc;
        }
        printf(" [✓] Identity keypair generated successfully.\n");
    } else {
        printf(" [✓] Found existing identity keypair.\n");
        qseal_identity_load(&ident);
    }
    printf(" [✓] Fingerprint: %s\n", ident.fingerprint);

    int s_rc = qseal_config_save_atomic(&cfg, resolved_config_path);
    if (s_rc != QSEAL_SUCCESS) {
        fprintf(stderr, "Error saving configuration to '%s': %s\n", resolved_config_path, qseal_strerror(s_rc));
        return s_rc;
    }

    int v_rc = qseal_config_validate(&cfg);
    if (v_rc != QSEAL_SUCCESS) {
        fprintf(stderr, "Configuration validation failed: %s\n", qseal_strerror(v_rc));
        return v_rc;
    }

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                         QSEAL INITIALIZATION COMPLETE                            ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════╝\n");
    printf(" Configuration saved to: %s\n\n", resolved_config_path);
    printf(" To start the node, execute:\n");
    if (cfg.role == QSEAL_ROLE_SERVER) {
        printf("   qseal server start --config %s\n\n", resolved_config_path);
        printf(" Or as a systemd service:\n");
        printf("   sudo systemctl start qseal-server\n");
    } else {
        printf("   qseal client connect --config %s\n\n", resolved_config_path);
        printf(" Or send a single message:\n");
        printf("   qseal client connect --config %s --msg \"Hello QSEAL Server\"\n", resolved_config_path);
    }
    printf("══════════════════════════════════════════════════════════════════════════════════\n\n");
    return QSEAL_SUCCESS;
}
