/*
 * securecomm/src/setup/setup_wizard.h
 *
 * Interactive and automated Setup Wizard for SecureComm.
 */

#ifndef SECURECOMM_SETUP_WIZARD_H
#define SECURECOMM_SETUP_WIZARD_H

#include "securecomm/config.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int securecomm_setup_wizard_run(const char *config_path, bool non_interactive);

int securecomm_setup_init_server(const char *config_path,
                                 uint16_t port,
                                 const char *bind_addr,
                                 const char *adv_endpoint,
                                 securecomm_mode_t mode,
                                 const char *device_id);

int securecomm_setup_init_client(const char *config_path,
                                 const char *server_host,
                                 uint16_t port,
                                 securecomm_mode_t mode,
                                 const char *device_id,
                                 const char *expected_server_id);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_SETUP_WIZARD_H */
