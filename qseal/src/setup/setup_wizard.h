/*
 * qseal/src/setup/setup_wizard.h
 *
 * Interactive and automated Setup Wizard for QSEAL.
 */

#ifndef QSEAL_SETUP_WIZARD_H
#define QSEAL_SETUP_WIZARD_H

#include "qseal/config.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int qseal_setup_wizard_run(const char *config_path, bool non_interactive);

int qseal_setup_init_server(const char *config_path,
                            uint16_t port,
                            const char *bind_addr,
                            const char *adv_endpoint,
                            qseal_mode_t mode,
                            const char *device_id);

int qseal_setup_init_client(const char *config_path,
                            const char *server_host,
                            uint16_t port,
                            qseal_mode_t mode,
                            const char *device_id,
                            const char *expected_server_id);

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
#define qseal_setup_wizard_run qseal_setup_wizard_run
#define qseal_setup_init_server qseal_setup_init_server
#define qseal_setup_init_client qseal_setup_init_client

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_SETUP_WIZARD_H */
