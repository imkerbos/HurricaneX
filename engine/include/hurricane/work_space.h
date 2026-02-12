#ifndef HURRICANE_WORK_SPACE_H
#define HURRICANE_WORK_SPACE_H

#include "common.h"
#include "socket.h"
#include "socket_table.h"
#include "mbuf_cache.h"
#include "pktio.h"
#include "http.h"

/*
 * Per-worker context — inspired by dperf work_space.
 *
 * Each lcore gets its own work_space with:
 *   - 3 packet templates (SYN/DATA/ACK)
 *   - TX queue for batch sending
 *   - Socket table for O(1) connection lookup
 *   - Statistics
 *
 * Single-threaded per-core, zero locks.
 */

/* TX queue — accumulate packets, flush in batch */
#define HX_TX_QUEUE_SIZE  4096
#define HX_TX_BURST       8

struct hx_tx_queue {
    hx_u16  head;
    hx_u16  tail;
    hx_pkt_t *buf[HX_TX_QUEUE_SIZE];
};

/* Per-worker statistics */
struct hx_ws_stats {
    hx_u64  conns_attempted;
    hx_u64  conns_established;
    hx_u64  conns_closed;
    hx_u64  conns_failed;
    hx_u64  conns_reset;
    hx_u64  conns_retransmit;
    hx_u64  http_req_sent;
    hx_u64  http_resp_recv;
    hx_u64  http_resp_2xx;
    hx_u64  http_resp_other;
    hx_u64  pkts_tx;
    hx_u64  pkts_rx;
    hx_u64  rx_loop_iters;
    double  elapsed_sec;
};

/* Work space configuration */
struct hx_ws_config {
    /* Network */
    hx_u32  src_ip;              /* host byte order */
    hx_u32  dst_ip;              /* host byte order */
    hx_u16  dst_port;            /* host byte order */
    hx_u16  src_port_base;       /* host byte order */
    hx_u32  num_conns;
    hx_u32  duration_sec;        /* 0 = until all done */
    hx_u8   src_mac[6];
    hx_u8   dst_mac[6];

    /* HTTP */
    bool    http_enabled;
    char    http_host[256];
    char    http_path[1024];
    hx_http_method_t http_method;
    char    http_extra_headers[2048];
    hx_u32  http_requests_per_conn; /* 0=unlimited, 1=no keep-alive */

    /* Rate control */
    hx_u32  launch_batch;        /* connections per launch (0=all at once) */
};

/* Work space — per-worker context */
struct hx_work_space {
    /* Identity */
    hx_u8   id;                  /* worker ID */
    bool    running;

    /* Packet I/O */
    hx_pktio_t *pktio;

    /* Packet templates */
    struct hx_mbuf_cache tcp_syn;    /* SYN (with MSS option) */
    struct hx_mbuf_cache tcp_data;   /* PSH+ACK (with HTTP payload) */
    struct hx_mbuf_cache tcp_ack;    /* ACK/FIN (bare header) */

    /* Pre-built HTTP request (for tcp_data template) */
    hx_u8   http_req_buf[2048];
    hx_u32  http_req_len;

    /* TX queue */
    struct hx_tx_queue txq;

    /* Socket table */
    struct hx_socket_table *st;

    /* IP ID counter */
    hx_u16  ip_id;

    /* Config */
    struct hx_ws_config cfg;

    /* Statistics */
    struct hx_ws_stats stats;

    /* Pkt descriptor ring for TX (avoids malloc) */
    hx_pkt_t pkt_descs[HX_TX_QUEUE_SIZE];
    hx_u16   pkt_desc_idx;
};

/*
 * Initialize work space.
 * Sets up socket table, packet templates, TX queue.
 */
hx_result_t hx_ws_init(struct hx_work_space *ws, hx_pktio_t *pktio,
                         const struct hx_ws_config *cfg);

/*
 * Run the client main loop.
 * RX burst → process → launch connections → TX flush → timer check.
 */
hx_result_t hx_ws_run(struct hx_work_space *ws);

/* Stop the work space */
void hx_ws_stop(struct hx_work_space *ws);

/* Get statistics */
struct hx_ws_stats hx_ws_get_stats(const struct hx_work_space *ws);

/* Cleanup */
void hx_ws_cleanup(struct hx_work_space *ws);

/* Single RX step — process one burst of incoming packets */
int hx_ws_rx_step(struct hx_work_space *ws);

/* --- TX queue operations (inline for hot path) --- */

static inline hx_pkt_t *hx_ws_alloc_pkt_desc(struct hx_work_space *ws)
{
    hx_pkt_t *p = &ws->pkt_descs[ws->pkt_desc_idx];
    ws->pkt_desc_idx = (ws->pkt_desc_idx + 1) % HX_TX_QUEUE_SIZE;
    return p;
}

static inline void hx_tx_queue_push(struct hx_work_space *ws, hx_pkt_t *pkt)
{
    ws->txq.buf[ws->txq.tail] = pkt;
    ws->txq.tail = (ws->txq.tail + 1) % HX_TX_QUEUE_SIZE;
    ws->stats.pkts_tx++;

    /* Auto-flush when batch is full */
    hx_u16 count = (ws->txq.tail - ws->txq.head + HX_TX_QUEUE_SIZE) % HX_TX_QUEUE_SIZE;
    if (count >= HX_TX_BURST) {
        hx_pktio_tx_burst(ws->pktio, &ws->txq.buf[ws->txq.head], HX_TX_BURST);
        ws->txq.head = (ws->txq.head + HX_TX_BURST) % HX_TX_QUEUE_SIZE;
    }
}

static inline void hx_tx_queue_flush(struct hx_work_space *ws)
{
    while (ws->txq.head != ws->txq.tail) {
        hx_u16 count = (ws->txq.tail - ws->txq.head + HX_TX_QUEUE_SIZE) % HX_TX_QUEUE_SIZE;
        if (count > HX_TX_BURST)
            count = HX_TX_BURST;

        int sent = hx_pktio_tx_burst(ws->pktio,
                                      &ws->txq.buf[ws->txq.head], count);
        if (sent <= 0)
            break;
        ws->txq.head = (ws->txq.head + (hx_u16)sent) % HX_TX_QUEUE_SIZE;
    }
    hx_pktio_tx_flush(ws->pktio);
}

#endif /* HURRICANE_WORK_SPACE_H */
