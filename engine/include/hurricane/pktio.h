#ifndef HURRICANE_PKTIO_H
#define HURRICANE_PKTIO_H

#include "common.h"
#include "mempool.h"

/*
 * Packet I/O abstraction layer.
 *
 * In production, backed by DPDK rte_ethdev.
 * For development/testing, backed by a mock (socket/loopback).
 */

/* Opaque packet buffer — wraps rte_mbuf in DPDK mode */
typedef struct hx_pkt {
    hx_u8  *data;
    hx_u32  len;
    hx_u32  buf_len;
    void   *opaque;   /* backend private: rte_mbuf* in DPDK mode, NULL otherwise */
} hx_pkt_t;

/* Opaque packet I/O context */
typedef struct hx_pktio hx_pktio_t;

/* Packet I/O operations vtable */
typedef struct hx_pktio_ops {
    hx_result_t (*init)(hx_pktio_t *io, const char *dev, hx_mempool_t *mp);
    void        (*close)(hx_pktio_t *io);
    hx_result_t (*alloc_pkt)(hx_pktio_t *io, hx_pkt_t *pkt, hx_u32 size);
    int         (*rx_burst)(hx_pktio_t *io, hx_pkt_t **pkts, int max_pkts);
    int         (*tx_burst)(hx_pktio_t *io, hx_pkt_t **pkts, int num_pkts);
    void        (*free_pkt)(hx_pktio_t *io, hx_pkt_t *pkt);
    void        (*tx_flush)(hx_pktio_t *io);  /* flush buffered TX packets */
} hx_pktio_ops_t;

struct hx_pktio {
    const hx_pktio_ops_t *ops;
    hx_mempool_t         *mp;
    void                 *priv;    /* backend-specific data */
};

/* Initialize packet I/O with the given backend ops */
hx_result_t hx_pktio_init(hx_pktio_t *io, const hx_pktio_ops_t *ops,
                           const char *dev, hx_mempool_t *mp);

/* Shutdown packet I/O */
void hx_pktio_close(hx_pktio_t *io);

/* Allocate a packet buffer from the backend */
hx_result_t hx_pktio_alloc_pkt(hx_pktio_t *io, hx_pkt_t *pkt, hx_u32 size);

/*
 * Receive a burst of packets. Returns number received (0..max_pkts).
 *
 * Ownership: caller owns the returned packets and MUST free each one
 * via hx_pktio_free_pkt() after processing. Failing to do so will
 * leak mbufs in DPDK mode (~8191 packets until pool exhaustion).
 */
int hx_pktio_rx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int max_pkts);

/* Transmit a burst of packets. Returns number sent (0..num_pkts). */
int hx_pktio_tx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int num_pkts);

/* Flush any buffered TX packets. Call at end of each main-loop iteration. */
void hx_pktio_tx_flush(hx_pktio_t *io);

/*
 * Free a single packet back to the backend.
 * Must be called for every packet obtained from hx_pktio_rx_burst()
 * or hx_pktio_alloc_pkt() once the caller is done with it.
 */
void hx_pktio_free_pkt(hx_pktio_t *io, hx_pkt_t *pkt);

/* Mock backend ops — for development/testing */
extern const hx_pktio_ops_t hx_pktio_mock_ops;

/* DPDK backend ops — available when compiled with HX_USE_DPDK */
#ifdef HX_USE_DPDK
extern const hx_pktio_ops_t hx_pktio_dpdk_ops;
#endif

#endif /* HURRICANE_PKTIO_H */
