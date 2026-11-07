/*
 * qseal/src/logging/logging.c
 *
 * Thread-safe, structured logger for QSEAL.
 */

#define _POSIX_C_SOURCE 200809L
#include "qseal/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <strings.h>

static qseal_log_level_t g_current_level = QSEAL_LOG_INFO;
static FILE *g_log_file = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *level_to_str(qseal_log_level_t level) {
    switch (level) {
        case QSEAL_LOG_DEBUG: return "DEBUG";
        case QSEAL_LOG_INFO:  return "INFO ";
        case QSEAL_LOG_WARN:  return "WARN ";
        case QSEAL_LOG_ERROR: return "ERROR";
        default:                   return "LOG  ";
    }
}

const char *qseal_log_level_to_string(qseal_log_level_t level) {
    switch (level) {
        case QSEAL_LOG_DEBUG: return "debug";
        case QSEAL_LOG_INFO:  return "info";
        case QSEAL_LOG_WARN:  return "warn";
        case QSEAL_LOG_ERROR: return "error";
        case QSEAL_LOG_NONE:  return "none";
        default:                   return "info";
    }
}

qseal_log_level_t qseal_log_level_from_string(const char *str) {
    if (!str) return QSEAL_LOG_INFO;
    if (strcasecmp(str, "debug") == 0) return QSEAL_LOG_DEBUG;
    if (strcasecmp(str, "info") == 0)  return QSEAL_LOG_INFO;
    if (strcasecmp(str, "warn") == 0 || strcasecmp(str, "warning") == 0) return QSEAL_LOG_WARN;
    if (strcasecmp(str, "error") == 0) return QSEAL_LOG_ERROR;
    if (strcasecmp(str, "none") == 0)  return QSEAL_LOG_NONE;
    return QSEAL_LOG_INFO;
}

int qseal_log_init(qseal_log_level_t level, const char *log_filepath) {
    pthread_mutex_lock(&g_log_mutex);
    g_current_level = level;
    if (g_log_file && g_log_file != stderr && g_log_file != stdout) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    
    if (log_filepath && strlen(log_filepath) > 0) {
        g_log_file = fopen(log_filepath, "a");
        if (!g_log_file) {
            pthread_mutex_unlock(&g_log_mutex);
            return -1;
        }
    }
    pthread_mutex_unlock(&g_log_mutex);
    return 0;
}

void qseal_log_close(void) {
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_file && g_log_file != stderr && g_log_file != stdout) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    pthread_mutex_unlock(&g_log_mutex);
}

void qseal_log_set_level(qseal_log_level_t level) {
    pthread_mutex_lock(&g_log_mutex);
    g_current_level = level;
    pthread_mutex_unlock(&g_log_mutex);
}

qseal_log_level_t qseal_log_get_level(void) {
    return g_current_level;
}

void qseal_log_write(qseal_log_level_t level, const char *module,
                          const char *file, int line, const char *fmt, ...) {
    (void)file;
    (void)line;
    if (level < g_current_level || level >= QSEAL_LOG_NONE) {
        return;
    }

    char time_buf[32];
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

    char msg_buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
    va_end(args);

    pthread_mutex_lock(&g_log_mutex);
    
    /* Format: [TIMESTAMP] [LEVEL] [MODULE] message */
    FILE *dest = (level >= QSEAL_LOG_WARN) ? stderr : stdout;
    fprintf(dest, "[%s] [%s] [%s] %s\n", time_buf, level_to_str(level), module ? module : "CORE", msg_buf);
    fflush(dest);
    
    if (g_log_file) {
        fprintf(g_log_file, "[%s] [%s] [%s] %s\n", time_buf, level_to_str(level), module ? module : "CORE", msg_buf);
        fflush(g_log_file);
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}
