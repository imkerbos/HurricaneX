/*
 * AF_XDP packet I/O backend — high-performance kernel bypass on Linux 5.4+.
 *
 * Uses XDP sockets (AF_XDP) with UMEM shared memory for zero-copy
 * packet TX/RX. Requires libxdp + libbpf. Needs CAP_NET_RAW or root.
 *
 * Device string format: "xdp:<ifname>" e.g. "xdp:eth0"
 *
 * Architecture:
 *   UMEM: contiguous memory region divided into fixed-size frames.
 *   4 lock-free rings shared with kernel:
 *     - FILL ring:       userspace → kernel (empty frames for RX)
 *     - COMPLETION ring: kernel → userspace (TX-done frames to reclaim)
 *     - RX ring:         kernel → userspace (received packets)
 *     - TX ring:         userspace → kernel (packets to send)
 */
#ifdef HX_USE_XDP

#include "hurricane/pktio.h"
#include "hurricane/log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <poll.h>

#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#define HX_LOG_COMP_XDP "pktio.xdp"

/* UMEM configuration */
#define XDP_NUM_FRAMES      16384
#define XDP_FRAME_SIZE      2048
#define XDP_FILL_RING_SIZE  4096
#define XDP_COMP_RING_SIZE  4096
#define XDP_RX_RING_SIZE    4096
#define XDP_TX_RING_SIZE    4096

/* Batch sizes */
#define XDP_RX_BATCH        64
#define XDP_TX_BATCH        64

/* RX packet descriptor pool (returned to caller) */
#define XDP_RX_DESC_POOL    64

typedef struct xdp_priv {
    struct xsk_socket      *xsk;
    struct xsk_umem        *umem;
    void                   *umem_area;

    /* Rings */
    struct xsk_ring_prod    fill_ring;
    struct xsk_ring_cons    comp_ring;
    struct xsk_ring_cons    rx_ring;
    struct xsk_ring_prod    tx_ring;

    /* Frame allocator — simple stack-based free list */
    uint64_t                frame_stack[XDP_NUM_FRAMES];
    uint32_t                frame_sp;   /* stack pointer */

    /* RX packet descriptors returned to caller */
    hx_pkt_t                rx_descs[XDP_RX_DESC_POOL];

    /* TX buffer for batching */
    hx_pkt_t               *tx_buf[XDP_TX_BATCH];
    uint16_t                tx_buf_count;

    /* Interface info */
    char                    ifname[IFNAMSIZ];
    int                     ifindex;
    uint32_t                queue_id;
} xdp_priv_t;

/* ---- Frame allocator ---- */

static void frame_pool_init(xdp_priv_t *priv)
{
    priv->frame_sp = XDP_NUM_FRAMES;
    for (uint32_t i = 0; i < XDP_NUM_FRAMES; i++)
        priv->frame_stack[i] = (uint64_t)i * XDP_FRAME_SIZE;
}

static uint64_t frame_alloc(xdp_priv_t *priv)
{
    if (priv->frame_sp == 0)
        return UINT64_MAX; /* exhausted */
    return priv->frame_stack[--priv->frame_sp];
}

static void frame_free(xdp_priv_t *priv, uint64_t addr)
{
    if (priv->frame_sp < XDP_NUM_FRAMES)
        priv->frame_stack[priv->frame_sp++] = addr;
}

/* ---- Fill ring: supply empty frames for kernel RX ---- */

static void xdp_populate_fill_ring(xdp_priv_t *priv)
{
    uint32_t idx;
    unsigned int avail = xsk_prod_nb_free(&priv->fill_ring,
                                           XDP_FILL_RING_SIZE / 2);
    if (avail == 0)
        return;

    if (xsk_ring_prod__reserve(&priv->fill_ring, avail, &idx) != avail)
        return;

    for (uint32_t i = 0; i < avail; i++) {
        uint64_t addr = frame_alloc(priv);
        if (addr == UINT64_MAX) {
            /* No more frames — submit what we have */
            xsk_ring_prod__submit(&priv->fill_ring, i);
            return;
        }
        *xsk_ring_prod__fill_addr(&priv->fill_ring, idx + i) = addr;
    }

    xsk_ring_prod__submit(&priv->fill_ring, avail);
}

/* ---- Completion ring: reclaim TX-done frames ---- */

static void xdp_reclaim_completion(xdp_priv_t *priv)
{
    uint32_t idx;
    unsigned int completed = xsk_ring_cons__peek(&priv->comp_ring,
                                                  XDP_COMP_RING_SIZE, &idx);
    if (completed == 0)
        return;

    for (uint32_t i = 0; i < completed; i++) {
        uint64_t addr = *xsk_ring_cons__comp_addr(&priv->comp_ring, idx + i);
        frame_free(priv, addr);
    }

    xsk_ring_cons__release(&priv->comp_ring, completed);
}

/* ---- pktio vtable implementation ---- */

static hx_result_t xdp_init(hx_pktio_t *io, const char *dev,
                              hx_mempool_t *mp)
{
    (void)mp;

    if (!dev)
        return HX_ERR_INVAL;

    /* Parse "xdp:<ifname>" */
    const char *prefix = "xdp:";
    if (strncmp(dev, prefix, 4) != 0) {
        HX_LOG_ERROR(HX_LOG_COMP_XDP,
                     "invalid device '%s', expected 'xdp:<ifname>'", dev);
        return HX_ERR_INVAL;
    }
    const char *ifname = dev + 4;
    if (strlen(ifname) == 0 || strlen(ifname) >= IFNAMSIZ)
        return HX_ERR_INVAL;

    xdp_priv_t *priv = calloc(1, sizeof(*priv));
    if (!priv)
        return HX_ERR_NOMEM;

    strncpy(priv->ifname, ifname, IFNAMSIZ - 1);
    priv->ifindex = (int)if_nametoindex(ifname);
    if (priv->ifindex == 0) {
        HX_LOG_ERROR(HX_LOG_COMP_XDP,
                     "interface '%s' not found: %s", ifname, strerror(errno));
        free(priv);
        return HX_ERR_INVAL;
    }
    priv->queue_id = 0; /* default to queue 0 */

    /* Initialize frame pool */
    frame_pool_init(priv);

    /* Allocate UMEM area (page-aligned) */
    size_t umem_size = (size_t)XDP_NUM_FRAMES * XDP_FRAME_SIZE;
    if (posix_memalign(&priv->umem_area, getpagesize(), umem_size) != 0) {
        HX_LOG_ERROR(HX_LOG_COMP_XDP, "posix_memalign failed for UMEM");
        free(priv);
        return HX_ERR_NOMEM;
    }
    memset(priv->umem_area, 0, umem_size);

    /* Create UMEM */
    struct xsk_umem_config umem_cfg = {
        .fill_size      = XDP_FILL_RING_SIZE,
        .comp_size      = XDP_COMP_RING_SIZE,
        .frame_size     = XDP_FRAME_SIZE,
        .frame_headroom = 0,
        .flags          = 0,
    };

    int ret = xsk_umem__create(&priv->umem, priv->umem_area, umem_size,
                                &priv->fill_ring, &priv->comp_ring,
                                &umem_cfg);
    if (ret != 0) {
        HX_LOG_ERROR(HX_LOG_COMP_XDP,
                     "xsk_umem__create failed: %s", strerror(-ret));
        free(priv->umem_area);
        free(priv);
        return HX_ERR_PKTIO;
    }

    /* Create XDP socket.
     *
     * SKB mode for maximum compatibility on cloud VMs (virtio, ena, etc).
     * Let libxdp auto-load the default XDP program that steers RX packets
     * into our socket — do NOT set INHIBIT_PROG_LOAD. */
    struct xsk_socket_config xsk_cfg = {
        .rx_size        = XDP_RX_RING_SIZE,
        .tx_size        = XDP_TX_RING_SIZE,
        .libbpf_flags   = 0,
        .xdp_flags      = XDP_FLAGS_SKB_MODE,
        .bind_flags     = XDP_USE_NEED_WAKEUP | XDP_COPY,
    };

    ret = xsk_socket__create(&priv->xsk, ifname, priv->queue_id,
                              priv->umem,
                              &priv->rx_ring, &priv->tx_ring,
                              &xsk_cfg);
    if (ret != 0) {
        HX_LOG_ERROR(HX_LOG_COMP_XDP,
                     "xsk_socket__create failed for '%s': %s "
                     "(need root or CAP_NET_RAW, kernel 5.4+)",
                     ifname, strerror(-ret));
        xsk_umem__delete(priv->umem);
        free(priv->umem_area);
        free(priv);
        return HX_ERR_PKTIO;
    }

    /* Pre-populate fill ring so kernel can start receiving */
    xdp_populate_fill_ring(priv);

    io->priv = priv;

    HX_LOG_INFO(HX_LOG_COMP_XDP,
                "AF_XDP socket opened on %s (ifindex=%d, queue=%u, "
                "umem=%u frames x %u bytes)",
                ifname, priv->ifindex, priv->queue_id,
                XDP_NUM_FRAMES, XDP_FRAME_SIZE);

    return HX_OK;
}

static void xdp_close(hx_pktio_t *io)
{
    if (!io || !io->priv)
        return;

    xdp_priv_t *priv = io->priv;

    if (priv->xsk)
        xsk_socket__delete(priv->xsk);
    if (priv->umem)
        xsk_umem__delete(priv->umem);

    HX_LOG_INFO(HX_LOG_COMP_XDP, "AF_XDP socket closed on %s", priv->ifname);

    free(priv->umem_area);
    free(priv);
    io->priv = NULL;
}

static hx_result_t xdp_alloc_pkt(hx_pktio_t *io, hx_pkt_t *pkt, hx_u32 size)
{
    xdp_priv_t *priv = io->priv;

    uint64_t addr = frame_alloc(priv);
    if (addr == UINT64_MAX)
        return HX_ERR_NOMEM;

    (void)size;
    pkt->data    = (hx_u8 *)priv->umem_area + addr;
    pkt->len     = 0;
    pkt->buf_len = XDP_FRAME_SIZE;
    pkt->opaque  = (void *)addr; /* store UMEM offset for TX */
    return HX_OK;
}

static int xdp_rx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int max_pkts)
{
    xdp_priv_t *priv = io->priv;
    uint32_t idx;
    int received = 0;

    /* Reclaim TX-done frames every RX burst to keep frame pool healthy */
    xdp_reclaim_completion(priv);

    if (max_pkts > XDP_RX_DESC_POOL)
        max_pkts = XDP_RX_DESC_POOL;

    unsigned int avail = xsk_ring_cons__peek(&priv->rx_ring,
                                              (uint32_t)max_pkts, &idx);
    if (avail == 0) {
        /* Replenish fill ring while idle */
        xdp_populate_fill_ring(priv);
        return 0;
    }

    for (uint32_t i = 0; i < avail; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&priv->rx_ring,
                                                              idx + i);
        hx_pkt_t *pkt = &priv->rx_descs[received];
        pkt->data    = (hx_u8 *)priv->umem_area + desc->addr;
        pkt->len     = desc->len;
        pkt->buf_len = XDP_FRAME_SIZE;
        pkt->opaque  = (void *)(uintptr_t)desc->addr; /* UMEM offset */
        pkts[received++] = pkt;
    }

    xsk_ring_cons__release(&priv->rx_ring, avail);

    /* Replenish fill ring */
    xdp_populate_fill_ring(priv);

    return received;
}

static int xdp_tx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int num_pkts)
{
    xdp_priv_t *priv = io->priv;
    int buffered = 0;

    for (int i = 0; i < num_pkts; i++) {
        if (priv->tx_buf_count >= XDP_TX_BATCH)
            break;
        priv->tx_buf[priv->tx_buf_count++] = pkts[i];
        buffered++;
    }

    return buffered;
}

static void xdp_tx_flush(hx_pktio_t *io)
{
    xdp_priv_t *priv = io->priv;

    if (priv->tx_buf_count == 0)
        return;

    /* Reclaim completed TX frames first */
    xdp_reclaim_completion(priv);

    uint32_t idx;
    unsigned int reserved = xsk_ring_prod__reserve(&priv->tx_ring,
                                                    priv->tx_buf_count, &idx);
    if (reserved == 0) {
        /* TX ring full — drop this batch, free frames */
        for (uint16_t i = 0; i < priv->tx_buf_count; i++) {
            hx_pkt_t *pkt = priv->tx_buf[i];
            if (pkt && pkt->opaque)
                frame_free(priv, (uint64_t)(uintptr_t)pkt->opaque);
        }
        priv->tx_buf_count = 0;
        return;
    }

    for (uint32_t i = 0; i < reserved; i++) {
        hx_pkt_t *pkt = priv->tx_buf[i];
        struct xdp_desc *desc = xsk_ring_prod__tx_desc(&priv->tx_ring,
                                                        idx + i);
        desc->addr = (uint64_t)(uintptr_t)pkt->opaque;
        desc->len  = pkt->len;
    }

    xsk_ring_prod__submit(&priv->tx_ring, reserved);

    /* Kick kernel if needed */
    if (xsk_ring_prod__needs_wakeup(&priv->tx_ring))
        sendto(xsk_socket__fd(priv->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    /* Free any un-submitted packets (if reserved < tx_buf_count) */
    for (uint16_t i = (uint16_t)reserved; i < priv->tx_buf_count; i++) {
        hx_pkt_t *pkt = priv->tx_buf[i];
        if (pkt && pkt->opaque)
            frame_free(priv, (uint64_t)(uintptr_t)pkt->opaque);
    }

    priv->tx_buf_count = 0;
}

static void xdp_free_pkt(hx_pktio_t *io, hx_pkt_t *pkt)
{
    if (!io || !io->priv || !pkt)
        return;

    xdp_priv_t *priv = io->priv;

    /* Return UMEM frame to free list */
    if (pkt->opaque) {
        frame_free(priv, (uint64_t)(uintptr_t)pkt->opaque);
        pkt->opaque = NULL;
    }
}

const hx_pktio_ops_t hx_pktio_xdp_ops = {
    .init      = xdp_init,
    .close     = xdp_close,
    .alloc_pkt = xdp_alloc_pkt,
    .rx_burst  = xdp_rx_burst,
    .tx_burst  = xdp_tx_burst,
    .free_pkt  = xdp_free_pkt,
    .tx_flush  = xdp_tx_flush,
};

#endif /* HX_USE_XDP */
