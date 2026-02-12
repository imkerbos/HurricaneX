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
} hx_pkt_t;

/* Opaque packet I/O context */
typedef struct hx_pktio hx_pktio_t;

/* Packet I/O operations vtable */
typedef struct hx_pktio_ops {
    hx_result_t (*init)(hx_pktio_t *io, const char *dev, hx_mempool_t *mp);
    void        (*close)(hx_pktio_t *io);
    int         (*rx_burst)(hx_pktio_t *io, hx_pkt_t **pkts, int max_pkts);
    int         (*tx_burst)(hx_pktio_t *io, hx_pkt_t **pkts, int num_pkts);
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

/* Receive a burst of packets. Returns number received (0..max_pkts). */
int hx_pktio_rx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int max_pkts);

/* Transmit a burst of packets. Returns number sent (0..num_pkts). */
int hx_pktio_tx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int num_pkts);

/* Mock backend ops — for development/testing */
extern const hx_pktio_ops_t hx_pktio_mock_ops;

#endif /* HURRICANE_PKTIO_H */
