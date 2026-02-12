#ifdef HX_USE_DPDK

#include "hurricane/pktio.h"
#include "hurricane/dpdk.h"
#include "hurricane/log.h"

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define HX_LOG_COMP_DPDK_IO "pktio.dpdk"

/* Per-port mbuf pool sizing */
#define DPDK_NUM_MBUFS      65535
#define DPDK_MBUF_CACHE_SZ  250

/* RX/TX descriptor ring sizes */
#define DPDK_RX_DESC  1024
#define DPDK_TX_DESC  1024

typedef struct dpdk_priv {
    uint16_t            port_id;
    uint16_t            rx_queue_id;    /* Phase 1: fixed 0 */
    uint16_t            tx_queue_id;    /* Phase 1: fixed 0 */
    struct rte_mempool *mbuf_pool;
    hx_pkt_t            pkt_descs[HX_MAX_BURST]; /* reusable RX descriptors */
} dpdk_priv_t;

/*
 * Parse device string "dpdk:<port_id>" → port_id.
 * Returns HX_OK on success.
 */
static hx_result_t parse_dev_string(const char *dev, uint16_t *port_id)
{
    if (!dev || !port_id)
        return HX_ERR_INVAL;

    const char *prefix = "dpdk:";
    size_t plen = strlen(prefix);

    if (strncmp(dev, prefix, plen) != 0) {
        HX_LOG_ERROR(HX_LOG_COMP_DPDK_IO,
                     "invalid device string '%s', expected 'dpdk:<port_id>'", dev);
        return HX_ERR_INVAL;
    }

    char *end = NULL;
    unsigned long val = strtoul(dev + plen, &end, 10);
    if (end == dev + plen || *end != '\0' || val > UINT16_MAX) {
        HX_LOG_ERROR(HX_LOG_COMP_DPDK_IO,
                     "invalid port_id in device string '%s'", dev);
        return HX_ERR_INVAL;
    }

    *port_id = (uint16_t)val;
    return HX_OK;
}

static hx_result_t dpdk_init(hx_pktio_t *io, const char *dev,
                              hx_mempool_t *mp)
{
    (void)mp; /* DPDK backend uses its own mbuf pool */

    if (!hx_dpdk_is_initialized()) {
        HX_LOG_ERROR(HX_LOG_COMP_DPDK_IO,
                     "DPDK EAL not initialized, call hx_dpdk_init() first");
        return HX_ERR_DPDK;
    }

    uint16_t port_id;
    hx_result_t rc = parse_dev_string(dev, &port_id);
    if (rc != HX_OK)
        return rc;

    if (!rte_eth_dev_is_valid_port(port_id)) {
        HX_LOG_ERROR(HX_LOG_COMP_DPDK_IO, "invalid DPDK port %u", port_id);
        return HX_ERR_INVAL;
    }

    dpdk_priv_t *priv = calloc(1, sizeof(*priv));
    if (!priv)
        return HX_ERR_NOMEM;

    priv->port_id = port_id;
    priv->rx_queue_id = 0;
    priv->tx_queue_id = 0;

    /* Create mbuf pool on the port's NUMA socket */
    int socket_id = rte_eth_dev_socket_id(port_id);
    if (socket_id < 0)
        socket_id = 0;

    char pool_name[64];
    snprintf(pool_name, sizeof(pool_name), "hx_mbuf_pool_%u", port_id);

    priv->mbuf_pool = rte_pktmbuf_pool_create(
        pool_name, DPDK_NUM_MBUFS, DPDK_MBUF_CACHE_SZ, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);

    if (!priv->mbuf_pool) {
        HX_LOG_ERROR(HX_LOG_COMP_DPDK_IO,
                     "failed to create mbuf pool for port %u", port_id);
        free(priv);
        return HX_ERR_DPDK;
    }

    /* Configure port: 1 RX queue, 1 TX queue */
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));

    int ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0) {
        HX_LOG_ERROR(HX_LOG_COMP_DPDK_IO,
                     "rte_eth_dev_configure failed for port %u: %d",
                     port_id, ret);
        rte_mempool_free(priv->mbuf_pool);
        free(priv);
        return HX_ERR_DPDK;
    }

    /* Setup RX queue */
    ret = rte_eth_rx_queue_setup(port_id, 0, DPDK_RX_DESC, socket_id,
                                  NULL, priv->mbuf_pool);
    if (ret < 0) {
        HX_LOG_ERROR(HX_LOG_COMP_DPDK_IO,
                     "rte_eth_rx_queue_setup failed for port %u: %d",
                     port_id, ret);
        rte_mempool_free(priv->mbuf_pool);
        free(priv);
        return HX_ERR_DPDK;
    }

    /* Setup TX queue */
    ret = rte_eth_tx_queue_setup(port_id, 0, DPDK_TX_DESC, socket_id, NULL);
    if (ret < 0) {
        HX_LOG_ERROR(HX_LOG_COMP_DPDK_IO,
                     "rte_eth_tx_queue_setup failed for port %u: %d",
                     port_id, ret);
        rte_mempool_free(priv->mbuf_pool);
        free(priv);
        return HX_ERR_DPDK;
    }

    /* Start the port */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        HX_LOG_ERROR(HX_LOG_COMP_DPDK_IO,
                     "rte_eth_dev_start failed for port %u: %d",
                     port_id, ret);
        rte_mempool_free(priv->mbuf_pool);
        free(priv);
        return HX_ERR_DPDK;
    }

    /* Enable promiscuous mode */
    ret = rte_eth_promiscuous_enable(port_id);
    if (ret < 0) {
        HX_LOG_WARN(HX_LOG_COMP_DPDK_IO,
                     "rte_eth_promiscuous_enable failed for port %u: %d "
                     "(non-fatal)", port_id, ret);
    }

    io->priv = priv;

    HX_LOG_INFO(HX_LOG_COMP_DPDK_IO,
                "port %u started (socket %d, %u mbufs)",
                port_id, socket_id, DPDK_NUM_MBUFS);

    return HX_OK;
}

static void dpdk_close(hx_pktio_t *io)
{
    if (!io || !io->priv)
        return;

    dpdk_priv_t *priv = io->priv;
    uint16_t port_id = priv->port_id;

    int ret = rte_eth_dev_stop(port_id);
    if (ret < 0)
        HX_LOG_WARN(HX_LOG_COMP_DPDK_IO,
                     "rte_eth_dev_stop failed for port %u: %d", port_id, ret);

    rte_eth_dev_close(port_id);
    rte_mempool_free(priv->mbuf_pool);

    HX_LOG_INFO(HX_LOG_COMP_DPDK_IO, "port %u closed", port_id);

    free(priv);
    io->priv = NULL;
}

/*
 * RX burst — zero-copy path.
 * Each received mbuf is wrapped into a reusable hx_pkt_t descriptor.
 */
static int dpdk_rx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int max_pkts)
{
    dpdk_priv_t *priv = io->priv;

    if (max_pkts > HX_MAX_BURST)
        max_pkts = HX_MAX_BURST;

    struct rte_mbuf *mbufs[HX_MAX_BURST];
    uint16_t nb_rx = rte_eth_rx_burst(priv->port_id, priv->rx_queue_id,
                                       mbufs, (uint16_t)max_pkts);

    for (uint16_t i = 0; i < nb_rx; i++) {
        hx_pkt_t *desc = &priv->pkt_descs[i];
        desc->data    = rte_pktmbuf_mtod(mbufs[i], hx_u8 *);
        desc->len     = (hx_u32)rte_pktmbuf_pkt_len(mbufs[i]);
        desc->buf_len = (hx_u32)rte_pktmbuf_data_len(mbufs[i]);
        desc->opaque  = mbufs[i];
        pkts[i] = desc;
    }

    return (int)nb_rx;
}

/*
 * TX burst — dual path:
 *   - opaque != NULL: mbuf already backing the packet (zero-copy)
 *   - opaque == NULL: data from hx_mempool, allocate mbuf + memcpy (compat path)
 */
static int dpdk_tx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int num_pkts)
{
    dpdk_priv_t *priv = io->priv;

    if (num_pkts > HX_MAX_BURST)
        num_pkts = HX_MAX_BURST;

    struct rte_mbuf *mbufs[HX_MAX_BURST];

    for (int i = 0; i < num_pkts; i++) {
        hx_pkt_t *pkt = pkts[i];

        if (pkt->opaque) {
            /* Zero-copy: mbuf already exists */
            struct rte_mbuf *m = (struct rte_mbuf *)pkt->opaque;
            /* Update mbuf length in case pkt->len was modified */
            rte_pktmbuf_data_len(m) = (uint16_t)pkt->len;
            rte_pktmbuf_pkt_len(m)  = pkt->len;
            mbufs[i] = m;
        } else {
            /* Compat path: allocate mbuf and copy data */
            struct rte_mbuf *m = rte_pktmbuf_alloc(priv->mbuf_pool);
            if (!m) {
                HX_LOG_WARN(HX_LOG_COMP_DPDK_IO,
                            "mbuf alloc failed during TX, dropping %d pkts",
                            num_pkts - i);
                num_pkts = i;
                break;
            }
            char *dst = rte_pktmbuf_append(m, pkt->len);
            if (!dst) {
                rte_pktmbuf_free(m);
                num_pkts = i;
                break;
            }
            memcpy(dst, pkt->data, pkt->len);
            mbufs[i] = m;
        }
    }

    if (num_pkts == 0)
        return 0;

    uint16_t nb_tx = rte_eth_tx_burst(priv->port_id, priv->tx_queue_id,
                                       mbufs, (uint16_t)num_pkts);

    /* Free unsent mbufs */
    for (uint16_t i = nb_tx; i < (uint16_t)num_pkts; i++)
        rte_pktmbuf_free(mbufs[i]);

    return (int)nb_tx;
}

static hx_result_t dpdk_alloc_pkt(hx_pktio_t *io, hx_pkt_t *pkt, hx_u32 size)
{
    dpdk_priv_t *priv = io->priv;
    struct rte_mbuf *m = rte_pktmbuf_alloc(priv->mbuf_pool);
    if (!m)
        return HX_ERR_NOMEM;
    char *data = rte_pktmbuf_append(m, size);
    if (!data) {
        rte_pktmbuf_free(m);
        return HX_ERR_NOMEM;
    }
    pkt->data    = (hx_u8 *)data;
    pkt->len     = 0;
    pkt->buf_len = size;
    pkt->opaque  = m;
    return HX_OK;
}

static void dpdk_free_pkt(hx_pktio_t *io, hx_pkt_t *pkt)
{
    (void)io;
    if (pkt && pkt->opaque) {
        rte_pktmbuf_free((struct rte_mbuf *)pkt->opaque);
        pkt->opaque = NULL;
        pkt->data = NULL;
        pkt->len = 0;
    }
}

const hx_pktio_ops_t hx_pktio_dpdk_ops = {
    .init      = dpdk_init,
    .close     = dpdk_close,
    .alloc_pkt = dpdk_alloc_pkt,
    .rx_burst  = dpdk_rx_burst,
    .tx_burst  = dpdk_tx_burst,
    .free_pkt  = dpdk_free_pkt,
};

#endif /* HX_USE_DPDK */
