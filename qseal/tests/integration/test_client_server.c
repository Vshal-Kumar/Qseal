/*
 * qseal/tests/integration/test_client_server.c
 *
 * Real end-to-end integration tests for QSEAL client-server communication.
 * Exercises Classical, Pure PQC, Hybrid, and Adaptive modes with real cryptography and UDP transport.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "qseal/server.h"
#include "qseal/client.h"
#include "qseal/config.h"
#include "qseal/identity.h"
#include "qseal/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>

typedef struct {
    qseal_server_t *server;
    int run_result;
} server_thread_ctx_t;

static void *server_thread_fn(void *arg) {
    server_thread_ctx_t *ctx = (server_thread_ctx_t *)arg;
    ctx->run_result = qseal_server_run(ctx->server);
    return NULL;
}

static void test_mode_integration(qseal_mode_t mode, uint16_t port, const char *label) {
    printf("\n--- Testing Integration: %s (Port %u) ---\n", label, port);
    char test_dir[128];
    snprintf(test_dir, sizeof(test_dir), "/tmp/qseal_integ_%u", port);
    char clean_cmd[256];
    snprintf(clean_cmd, sizeof(clean_cmd), "rm -rf %s && mkdir -p %s", test_dir, test_dir);
    (void)system(clean_cmd);

    /* 1. Setup Server Configuration & Identity */
    qseal_config_t s_cfg;
    qseal_config_init_defaults(&s_cfg);
    s_cfg.role = QSEAL_ROLE_SERVER;
    s_cfg.mode = mode;
    s_cfg.port = port;
    strcpy(s_cfg.bind_address, "127.0.0.1");
    strcpy(s_cfg.device_id, "server-integ-node");
    s_cfg.allow_tofu = true;

    qseal_identity_t s_id;
    qseal_identity_init(&s_id, s_cfg.device_id, mode, test_dir);
    int rc = qseal_identity_generate(&s_id);
    assert(rc == QSEAL_SUCCESS);

    qseal_server_t *server = qseal_server_create(&s_cfg, &s_id);
    assert(server != NULL);

    /* Start server in background thread */
    server_thread_ctx_t s_ctx = { .server = server, .run_result = 0 };
    pthread_t s_tid;
    pthread_create(&s_tid, NULL, server_thread_fn, &s_ctx);

    /* Allow server socket to bind */
    usleep(100000); /* 100ms */

    /* 2. Setup Client Configuration & Identity */
    qseal_config_t c_cfg;
    qseal_config_init_defaults(&c_cfg);
    c_cfg.role = QSEAL_ROLE_CLIENT;
    c_cfg.mode = mode;
    c_cfg.port = port;
    strcpy(c_cfg.server_host, "127.0.0.1");
    strcpy(c_cfg.device_id, "client-integ-node");
    c_cfg.connection_timeout_ms = 3000;

    qseal_identity_t c_id;
    qseal_identity_init(&c_id, c_cfg.device_id, mode, test_dir);
    rc = qseal_identity_generate(&c_id);
    assert(rc == QSEAL_SUCCESS);

    qseal_client_t *client = qseal_client_create(&c_cfg, &c_id);
    assert(client != NULL);

    /* 3. Connect Client to Server */
    rc = qseal_client_connect(client);
    assert(rc == QSEAL_SUCCESS);
    assert(qseal_client_is_connected(client) == true);

    /* 4. Transmit Encrypted Application Messages */
    const char *test_msg1 = "Hello, QSEAL Quantum-Safe World!";
    rc = qseal_client_send(client, (const uint8_t *)test_msg1, strlen(test_msg1));
    assert(rc == QSEAL_SUCCESS);

    const char *test_msg2 = "Verifying AEAD authentication and replay window tracking.";
    rc = qseal_client_send(client, (const uint8_t *)test_msg2, strlen(test_msg2));
    assert(rc == QSEAL_SUCCESS);

    /* 5. Graceful Disconnect */
    qseal_client_disconnect(client);
    qseal_client_free(client);

    /* Stop server */
    qseal_server_stop(server);
    pthread_join(s_tid, NULL);
    qseal_server_free(server);

    printf(" [✓] Mode %s Integration Test PASSED!\n", label);
}

int main(void) {
    printf("=================================================================\n");
    printf("            QSEAL REAL CLIENT-SERVER INTEGRATION SUITE           \n");
    printf("=================================================================\n");

    test_mode_integration(QSEAL_MODE_CLASSICAL, 9871, "Classical (X25519/Ed25519/AES-CCM)");
    test_mode_integration(QSEAL_MODE_PQC,       9872, "Pure PQC (ML-KEM-768/ML-DSA-65)");
    test_mode_integration(QSEAL_MODE_HYBRID,    9873, "Hybrid (Combiner)");
    test_mode_integration(QSEAL_MODE_ADAPTIVE,  9874, "Adaptive Mode Selection");

    printf("\n=================================================================\n");
    printf("       ALL REAL INTEGRATION TESTS COMPLETED SUCCESSFULLY!        \n");
    printf("=================================================================\n");
    return 0;
}
