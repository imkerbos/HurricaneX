#include "hurricane/pktio.h"

hx_result_t hx_pktio_init(hx_pktio_t *io, const hx_pktio_ops_t *ops,
                           const char *dev, hx_mempool_t *mp)
{
    if (!io || !ops || !mp)
        return HX_ERR_INVAL;

    io->ops = ops;
    io->mp = mp;
    io->priv = NULL;

    return ops->init(io, dev, mp);
}

void hx_pktio_close(hx_pktio_t *io)
{
    if (io && io->ops && io->ops->close)
        io->ops->close(io);
}

int hx_pktio_rx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int max_pkts)
{
    if (!io || !io->ops || !io->ops->rx_burst)
        return 0;
    return io->ops->rx_burst(io, pkts, max_pkts);
}

int hx_pktio_tx_burst(hx_pktio_t *io, hx_pkt_t **pkts, int num_pkts)
{
    if (!io || !io->ops || !io->ops->tx_burst)
        return 0;
    return io->ops->tx_burst(io, pkts, num_pkts);
}

void hx_pktio_free_pkt(hx_pktio_t *io, hx_pkt_t *pkt)
{
    if (io && io->ops && io->ops->free_pkt)
        io->ops->free_pkt(io, pkt);
}
