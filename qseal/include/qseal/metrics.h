/*
 * qseal/include/qseal/metrics.h
 *
 * Performance, latency, memory RSS, and throughput monitoring for QSEAL.
 */

#ifndef QSEAL_METRICS_H
#define QSEAL_METRICS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t start_time_sec;
    uint64_t uptime_sec;
    
    /* Memory Metrics */
    uint64_t peak_rss_kb;
    uint64_t current_rss_kb;
    
    /* Network & Throughput */
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t packets_sent;
    uint64_t packets_recv;
    uint64_t packets_replayed;
    uint64_t packets_dropped;
    
    /* Handshake Metrics */
    uint32_t handshakes_attempted;
    uint32_t handshakes_succeeded;
    uint32_t handshakes_failed;
    double   avg_handshake_latency_ms;
    double   min_handshake_latency_ms;
    double   max_handshake_latency_ms;
    
    /* Concurrency */
    uint32_t active_sessions;
    uint32_t peak_concurrent_sessions;
} qseal_metrics_t;

void qseal_metrics_init(qseal_metrics_t *m);
void qseal_metrics_update_memory(qseal_metrics_t *m);
void qseal_metrics_record_handshake(qseal_metrics_t *m, double latency_ms, bool success);
void qseal_metrics_record_packet_tx(qseal_metrics_t *m, size_t bytes);
void qseal_metrics_record_packet_rx(qseal_metrics_t *m, size_t bytes);
void qseal_metrics_print(const qseal_metrics_t *m, FILE *out);

/* ─── Backward Compatibility Aliases ─────────────────────────────── */
typedef qseal_metrics_t securecomm_metrics_t;
#define securecomm_metrics_init             qseal_metrics_init
#define securecomm_metrics_update_memory    qseal_metrics_update_memory
#define securecomm_metrics_record_handshake qseal_metrics_record_handshake
#define securecomm_metrics_record_packet_tx qseal_metrics_record_packet_tx
#define securecomm_metrics_record_packet_rx qseal_metrics_record_packet_rx
#define securecomm_metrics_print            qseal_metrics_print

#ifdef __cplusplus
}
#endif

#endif /* QSEAL_METRICS_H */
