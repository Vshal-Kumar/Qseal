/*
 * qseal/src/main.c
 *
 * QSEAL: Lightweight, Adaptive, Cross-Platform Secure Communication Framework.
 * Standalone application entry point.
 */

#include "cli/cli.h"
#include "qseal/logging.h"

int main(int argc, char **argv) {
    qseal_log_init(QSEAL_LOG_INFO, NULL);
    return qseal_cli_dispatch(argc, argv);
}
