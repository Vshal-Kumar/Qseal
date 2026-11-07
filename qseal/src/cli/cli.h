/*
 * qseal/src/cli/cli.h
 *
 * Command-Line Interface dispatcher and subcommand handlers for QSEAL.
 */

#ifndef QSEAL_CLI_H
#define QSEAL_CLI_H

#ifdef __cplusplus
extern "C" {
#endif

int qseal_cli_dispatch(int argc, char **argv);

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
#define qseal_cli_dispatch qseal_cli_dispatch

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_CLI_H */
