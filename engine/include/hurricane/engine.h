#ifndef HURRICANE_ENGINE_H
#define HURRICANE_ENGINE_H

#include "common.h"
#include "pktio.h"
#include "conn_table.h"
#include "net.h"

/*
 * Engine — drives the RX/TX main loop and connection lifecycle.
 *
 * Creates connections, runs the packet processing loop, and collects
 * basic statistics. Designed for single-core operation (Phase 1).
 */

/* Engine configuration */
typedef struct hx_engine_config {
    hx_u32  dst_ip;
    hx_u16  dst_port;
    hx_u32  src_ip;
    hx_u16  src_port_base;   /* source ports: base .. base+num_conns-1 */
    hx_u32  num_conns;       /* number of connections to create */
    hx_u32  duration_sec;    /* test duration in seconds (0 = until all done) */
    hx_u8   src_mac[6];
    hx_u8   dst_mac[6];
} hx_engine_config_t;

/* Engine statistics */
typedef struct hx_engine_stats {
    hx_u64  conns_attempted;
    hx_u64  conns_established;
    hx_u64  conns_closed;
    hx_u64  conns_failed;
    hx_u64  conns_reset;
    hx_u64  pkts_tx;
    hx_u64  pkts_rx;
    hx_u64  rx_loop_iters;
    double   elapsed_sec;
} hx_engine_stats_t;

/* Engine context */
typedef struct hx_engine {
    hx_pktio_t         *pktio;
    hx_conn_table_t    *ct;
    hx_engine_config_t  cfg;
    hx_engine_stats_t   stats;
    bool                 running;
} hx_engine_t;

/* Initialize engine with pktio and config. */
hx_result_t hx_engine_init(hx_engine_t *eng, hx_pktio_t *pktio,
                            const hx_engine_config_t *cfg);

/* Create all connections and send SYNs. */
hx_result_t hx_engine_start(hx_engine_t *eng);

/*
 * Run one iteration of the RX loop:
 *   rx_burst → parse frames → lookup conn → tcp_input
 * Returns number of packets processed.
 */
int hx_engine_rx_step(hx_engine_t *eng);

/*
 * Run the main loop until all connections are done or duration expires.
 * Calls hx_engine_rx_step() in a tight loop.
 */
hx_result_t hx_engine_run(hx_engine_t *eng);

/* Stop the engine (sets running = false). */
void hx_engine_stop(hx_engine_t *eng);

/* Get a copy of current statistics. */
hx_engine_stats_t hx_engine_get_stats(const hx_engine_t *eng);

/* Cleanup engine resources. */
void hx_engine_cleanup(hx_engine_t *eng);

#endif /* HURRICANE_ENGINE_H */
