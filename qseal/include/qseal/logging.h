/*
 * qseal/include/qseal/logging.h
 *
 * Structured, lightweight logging for QSEAL.
 * Enforces secret suppression and thread-safe outputs.
 */

#ifndef QSEAL_LOGGING_H
#define QSEAL_LOGGING_H

#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QSEAL_LOG_DEBUG = 0,
    QSEAL_LOG_INFO  = 1,
    QSEAL_LOG_WARN  = 2,
    QSEAL_LOG_ERROR = 3,
    QSEAL_LOG_NONE  = 4
} qseal_log_level_t;

int  qseal_log_init(qseal_log_level_t level, const char *log_filepath);
void qseal_log_close(void);
void qseal_log_set_level(qseal_log_level_t level);
qseal_log_level_t qseal_log_get_level(void);
qseal_log_level_t qseal_log_level_from_string(const char *str);
const char *qseal_log_level_to_string(qseal_log_level_t level);

void qseal_log_write(qseal_log_level_t level, const char *module,
                     const char *file, int line, const char *fmt, ...)
                     __attribute__((format(printf, 5, 6)));

#define QSEAL_LOG_DEBUG(...) qseal_log_write(QSEAL_LOG_DEBUG, "CORE", __FILE__, __LINE__, __VA_ARGS__)
#define QSEAL_LOG_INFO(...)  qseal_log_write(QSEAL_LOG_INFO,  "CORE", __FILE__, __LINE__, __VA_ARGS__)
#define QSEAL_LOG_WARN(...)  qseal_log_write(QSEAL_LOG_WARN,  "CORE", __FILE__, __LINE__, __VA_ARGS__)
#define QSEAL_LOG_ERROR(...) qseal_log_write(QSEAL_LOG_ERROR, "CORE", __FILE__, __LINE__, __VA_ARGS__)

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
typedef qseal_log_level_t securecomm_log_level_t;
#define SECURECOMM_LOG_DEBUG QSEAL_LOG_DEBUG
#define SECURECOMM_LOG_INFO  QSEAL_LOG_INFO
#define SECURECOMM_LOG_WARN  QSEAL_LOG_WARN
#define SECURECOMM_LOG_ERROR QSEAL_LOG_ERROR
#define SECURECOMM_LOG_NONE  QSEAL_LOG_NONE

#define securecomm_log_init qseal_log_init
#define securecomm_log_close qseal_log_close
#define securecomm_log_set_level qseal_log_set_level
#define securecomm_log_get_level qseal_log_get_level
#define securecomm_log_level_from_string qseal_log_level_from_string
#define securecomm_log_level_to_string qseal_log_level_to_string
#define securecomm_log_write qseal_log_write

#define SECURECOMM_LOG_DEBUG QSEAL_LOG_DEBUG
#define SECURECOMM_LOG_INFO  QSEAL_LOG_INFO
#define SECURECOMM_LOG_WARN  QSEAL_LOG_WARN
#define SECURECOMM_LOG_ERROR QSEAL_LOG_ERROR

#define LOG_DEBUG(mod, ...) qseal_log_write(QSEAL_LOG_DEBUG, mod, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(mod, ...)  qseal_log_write(QSEAL_LOG_INFO,  mod, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(mod, ...)  qseal_log_write(QSEAL_LOG_WARN,  mod, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(mod, ...) qseal_log_write(QSEAL_LOG_ERROR, mod, __FILE__, __LINE__, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_LOGGING_H */
