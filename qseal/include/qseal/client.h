/*
 * qseal/include/qseal/client.h
 *
 * QSEAL Secure Client Engine.
 * Manages connection, mutual handshake, message streaming, and verified termination.
 */

#ifndef QSEAL_CLIENT_H
#define QSEAL_CLIENT_H

#include "config.h"
#include "identity.h"
#include "metrics.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qseal_client_s qseal_client_t;

qseal_client_t *qseal_client_create(const qseal_config_t *cfg,
                                    const qseal_identity_t *ident);
void            qseal_client_free(qseal_client_t *client);

/* Connect to remote server and complete mutual authentication */
int  qseal_client_connect(qseal_client_t *client);

/* Send encrypted application message */
int  qseal_client_send(qseal_client_t *client, const uint8_t *data, size_t len);

/* Receive decrypted application message (with timeout in ms) */
int  qseal_client_recv(qseal_client_t *client, uint8_t *buf, size_t buf_max,
                       size_t *out_len, int timeout_ms);

/* Run interactive chat / messaging loop */
int  qseal_client_run_interactive(qseal_client_t *client);

/* Disconnect and send graceful termination frame */
void qseal_client_disconnect(qseal_client_t *client);

/* State query */
bool qseal_client_is_connected(const qseal_client_t *client);
const qseal_metrics_t *qseal_client_get_metrics(const qseal_client_t *client);

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
typedef qseal_client_t securecomm_client_t;
#define securecomm_client_create          qseal_client_create
#define securecomm_client_free            qseal_client_free
#define securecomm_client_connect         qseal_client_connect
#define securecomm_client_send            qseal_client_send
#define securecomm_client_recv            qseal_client_recv
#define securecomm_client_run_interactive qseal_client_run_interactive
#define securecomm_client_disconnect      qseal_client_disconnect
#define securecomm_client_is_connected    qseal_client_is_connected
#define securecomm_client_get_metrics     qseal_client_get_metrics

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_CLIENT_H */
