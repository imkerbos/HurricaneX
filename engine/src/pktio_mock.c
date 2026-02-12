#include "hurricane/pktio.h"
#include <stdlib.h>
#include <string.h>

/*
 * Mock packet I/O backend for development and testing.
 *
 * Uses a simple loopback ring buffer: transmitted packets are queued
 * and can be received back, allowing local testing without DPDK or NICs.
 */

#define MOCK_RING_SIZE 1024

typedef struct mock_priv {
    hx_pkt_t *ring[MOCK_RING_SIZE];
    int        head;
    int        tail;
    int        count;
} mock_priv_t;

static hx_result_t mock_init(hx_pktio_t *io, const char *dev,
                              hx_mempool_t *mp)
{
    (void)dev;
    (void)mp;

    mock_priv_t *priv = calloc(1, sizeof(*priv));
    if (!priv)
        return HX_ERR_NOMEM;

    io->priv = priv;
    return HX_OK;
}

static void mock_close(hx_pktio_t *io)
{
    if (!io)
        return;
    free(io->priv);
    io->priv = NULL;
}

static int mock_rx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int max_pkts)
{
    mock_priv_t *priv = io->priv;
    int received = 0;

    while (received < max_pkts && priv->count > 0) {
        pkts[received] = priv->ring[priv->head];
        priv->head = (priv->head + 1) % MOCK_RING_SIZE;
        priv->count--;
        received++;
    }

    return received;
}

static int mock_tx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int num_pkts)
{
    mock_priv_t *priv = io->priv;
    int sent = 0;

    while (sent < num_pkts && priv->count < MOCK_RING_SIZE) {
        priv->ring[priv->tail] = pkts[sent];
        priv->tail = (priv->tail + 1) % MOCK_RING_SIZE;
        priv->count++;
        sent++;
    }

    return sent;
}

static hx_result_t mock_alloc_pkt(hx_pktio_t *io, hx_pkt_t *pkt, hx_u32 size)
{
    (void)size;
    if (!io || !io->mp || !pkt)
        return HX_ERR_INVAL;
    void *buf = hx_mempool_alloc(io->mp);
    if (!buf)
        return HX_ERR_NOMEM;
    pkt->data    = buf;
    pkt->len     = 0;
    pkt->buf_len = HX_MAX_PKT_SIZE;
    pkt->opaque  = NULL;
    return HX_OK;
}

static void mock_free_pkt(hx_pktio_t *io, hx_pkt_t *pkt)
{
    if (io && io->mp && pkt && pkt->data)
        hx_mempool_free(io->mp, pkt->data);
}

static void mock_tx_flush(hx_pktio_t *io)
{
    (void)io; /* mock tx_burst sends immediately, nothing to flush */
}

const hx_pktio_ops_t hx_pktio_mock_ops = {
    .init      = mock_init,
    .close     = mock_close,
    .alloc_pkt = mock_alloc_pkt,
    .rx_burst  = mock_rx_burst,
    .tx_burst  = mock_tx_burst,
    .free_pkt  = mock_free_pkt,
    .tx_flush  = mock_tx_flush,
};
