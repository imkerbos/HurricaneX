#ifndef HURRICANE_LOG_H
#define HURRICANE_LOG_H

#include "common.h"

/*
 * Structured JSON logging for HurricaneX engine.
 *
 * When compiled with HX_USE_DPDK, routes through rte_log.
 * Otherwise, outputs to stderr.
 *
 * All log output is single-line JSON (ndjson format):
 * {"ts":"2026-02-12T03:14:15.926535Z","level":"info","component":"tcp","msg":"..."}
 */

/* Log levels */
typedef enum {
    HX_LOG_LEVEL_DEBUG = 0,
    HX_LOG_LEVEL_INFO,
    HX_LOG_LEVEL_WARN,
    HX_LOG_LEVEL_ERROR,
    HX_LOG_LEVEL_FATAL,
} hx_log_level_t;

/* Compile-time minimum log level filter */
#ifndef HX_LOG_LEVEL_MIN
#ifdef NDEBUG
#define HX_LOG_LEVEL_MIN HX_LOG_LEVEL_INFO
#else
#define HX_LOG_LEVEL_MIN HX_LOG_LEVEL_DEBUG
#endif
#endif

/* Component name constants */
#define HX_LOG_COMP_TCP     "tcp"
#define HX_LOG_COMP_HTTP    "http"
#define HX_LOG_COMP_TLS     "tls"
#define HX_LOG_COMP_PKTIO   "pktio"
#define HX_LOG_COMP_MEMPOOL "mempool"
#define HX_LOG_COMP_CONFIG  "config"
#define HX_LOG_COMP_ENGINE  "engine"

/* Initialize the logging subsystem. Call once at startup. */
hx_result_t hx_log_init(hx_log_level_t level);

/* Return the string name of a log level. */
const char *hx_log_level_str(hx_log_level_t level);

/* Internal logging function — use macros below, not this directly. */
void hx_log_write(hx_log_level_t level, const char *component,
                  const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* Logging macros with compile-time level filtering */
#define HX_LOG_DEBUG(comp, fmt, ...) \
    do { \
        if (HX_LOG_LEVEL_DEBUG >= HX_LOG_LEVEL_MIN) \
            hx_log_write(HX_LOG_LEVEL_DEBUG, comp, fmt, ##__VA_ARGS__); \
    } while (0)

#define HX_LOG_INFO(comp, fmt, ...) \
    do { \
        if (HX_LOG_LEVEL_INFO >= HX_LOG_LEVEL_MIN) \
            hx_log_write(HX_LOG_LEVEL_INFO, comp, fmt, ##__VA_ARGS__); \
    } while (0)

#define HX_LOG_WARN(comp, fmt, ...) \
    do { \
        if (HX_LOG_LEVEL_WARN >= HX_LOG_LEVEL_MIN) \
            hx_log_write(HX_LOG_LEVEL_WARN, comp, fmt, ##__VA_ARGS__); \
    } while (0)

#define HX_LOG_ERROR(comp, fmt, ...) \
    do { \
        if (HX_LOG_LEVEL_ERROR >= HX_LOG_LEVEL_MIN) \
            hx_log_write(HX_LOG_LEVEL_ERROR, comp, fmt, ##__VA_ARGS__); \
    } while (0)

#define HX_LOG_FATAL(comp, fmt, ...) \
    do { \
        if (HX_LOG_LEVEL_FATAL >= HX_LOG_LEVEL_MIN) \
            hx_log_write(HX_LOG_LEVEL_FATAL, comp, fmt, ##__VA_ARGS__); \
    } while (0)

#endif /* HURRICANE_LOG_H */
