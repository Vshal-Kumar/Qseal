/*
 * qseal/include/qseal/server.h
 *
 * QSEAL High-Performance Server Engine.
 * Manages concurrent sessions, wire protocol dispatcher, and graceful shutdown.
 */

#ifndef QSEAL_SERVER_H
#define QSEAL_SERVER_H

#include "config.h"
#include "identity.h"
#include "metrics.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qseal_server_s qseal_server_t;

qseal_server_t *qseal_server_create(const qseal_config_t *cfg,
                                    const qseal_identity_t *ident);
void            qseal_server_free(qseal_server_t *server);

/* Start listening and enter server event loop (blocking until stop requested) */
int  qseal_server_run(qseal_server_t *server);

/* Request asynchronous stop */
void qseal_server_stop(qseal_server_t *server);

/* Inspect server state */
bool qseal_server_is_running(const qseal_server_t *server);
const qseal_metrics_t *qseal_server_get_metrics(const qseal_server_t *server);

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
typedef qseal_server_t securecomm_server_t;
#define securecomm_server_create      qseal_server_create
#define securecomm_server_free        qseal_server_free
#define securecomm_server_run         qseal_server_run
#define securecomm_server_stop        qseal_server_stop
#define securecomm_server_is_running  qseal_server_is_running
#define securecomm_server_get_metrics qseal_server_get_metrics

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_SERVER_H */
