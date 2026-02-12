#ifndef HURRICANE_DPDK_H
#define HURRICANE_DPDK_H

#include "common.h"

/*
 * DPDK EAL initialization wrapper.
 *
 * Must be called once before any DPDK pktio backend usage.
 * Thread-safe: uses pthread_once internally.
 */

typedef struct hx_dpdk_config {
    int     argc;
    char  **argv;    /* EAL arguments, e.g. -l 2-17 --socket-mem 16384,0 */
} hx_dpdk_config_t;

/* Initialize DPDK EAL. Safe to call multiple times (only first call takes effect). */
hx_result_t hx_dpdk_init(const hx_dpdk_config_t *cfg);

/* Check whether EAL has been initialized. */
bool hx_dpdk_is_initialized(void);

/* Cleanup DPDK EAL resources. Call once at shutdown. */
void hx_dpdk_cleanup(void);

#endif /* HURRICANE_DPDK_H */
