#include "hurricane/pktio.h"
#include "hurricane/mempool.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_mock_init_close(void)
{
    hx_mempool_t *mp = hx_mempool_create("pktio_test", 32, HX_MAX_PKT_SIZE);
    assert(mp != NULL);

    hx_pktio_t io;
    assert(hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp) == HX_OK);
    hx_pktio_close(&io);
    hx_mempool_destroy(mp);
    printf("  PASS: test_mock_init_close\n");
}

static void test_tx_rx_single(void)
{
    hx_mempool_t *mp = hx_mempool_create("pktio_test", 32, HX_MAX_PKT_SIZE);
    hx_pktio_t io;
    hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp);

    hx_pkt_t pkt;
    hx_u8 *buf = hx_mempool_alloc(mp);
    assert(buf != NULL);
    memcpy(buf, "packet-one", 10);
    pkt.data = buf;
    pkt.len = 10;
    pkt.buf_len = HX_MAX_PKT_SIZE;

    hx_pkt_t *tx[1] = { &pkt };
    assert(hx_pktio_tx_burst(&io, tx, 1) == 1);

    hx_pkt_t *rx[1];
    assert(hx_pktio_rx_burst(&io, rx, 1) == 1);
    assert(rx[0] == &pkt);
    assert(memcmp(rx[0]->data, "packet-one", 10) == 0);

    hx_mempool_free(mp, buf);
    hx_pktio_close(&io);
    hx_mempool_destroy(mp);
    printf("  PASS: test_tx_rx_single\n");
}

static void test_tx_rx_burst(void)
{
    hx_mempool_t *mp = hx_mempool_create("pktio_test", 64, HX_MAX_PKT_SIZE);
    hx_pktio_t io;
    hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp);

    /* Send 4 packets */
    hx_pkt_t pkts[4];
    hx_u8 *bufs[4];
    hx_pkt_t *tx_ptrs[4];

    for (int i = 0; i < 4; i++) {
        bufs[i] = hx_mempool_alloc(mp);
        assert(bufs[i] != NULL);
        snprintf((char *)bufs[i], 32, "pkt-%d", i);
        pkts[i].data = bufs[i];
        pkts[i].len = 5;
        pkts[i].buf_len = HX_MAX_PKT_SIZE;
        tx_ptrs[i] = &pkts[i];
    }

    assert(hx_pktio_tx_burst(&io, tx_ptrs, 4) == 4);

    /* Receive 2 at a time */
    hx_pkt_t *rx[4];
    int n1 = hx_pktio_rx_burst(&io, rx, 2);
    assert(n1 == 2);
    assert(rx[0] == &pkts[0]);
    assert(rx[1] == &pkts[1]);

    int n2 = hx_pktio_rx_burst(&io, rx, 4);
    assert(n2 == 2);
    assert(rx[0] == &pkts[2]);
    assert(rx[1] == &pkts[3]);

    /* Queue empty */
    assert(hx_pktio_rx_burst(&io, rx, 4) == 0);

    for (int i = 0; i < 4; i++)
        hx_mempool_free(mp, bufs[i]);
    hx_pktio_close(&io);
    hx_mempool_destroy(mp);
    printf("  PASS: test_tx_rx_burst\n");
}

static void test_rx_empty(void)
{
    hx_mempool_t *mp = hx_mempool_create("pktio_test", 8, HX_MAX_PKT_SIZE);
    hx_pktio_t io;
    hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp);

    hx_pkt_t *rx[4];
    assert(hx_pktio_rx_burst(&io, rx, 4) == 0);

    hx_pktio_close(&io);
    hx_mempool_destroy(mp);
    printf("  PASS: test_rx_empty\n");
}

static void test_null_safety(void)
{
    assert(hx_pktio_rx_burst(NULL, NULL, 0) == 0);
    assert(hx_pktio_tx_burst(NULL, NULL, 0) == 0);
    hx_pktio_close(NULL); /* should not crash */

    hx_pktio_t io;
    memset(&io, 0, sizeof(io));
    assert(hx_pktio_init(&io, NULL, "x", NULL) == HX_ERR_INVAL);
    printf("  PASS: test_null_safety\n");
}

static void test_fifo_order(void)
{
    hx_mempool_t *mp = hx_mempool_create("pktio_test", 32, HX_MAX_PKT_SIZE);
    hx_pktio_t io;
    hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp);

    hx_pkt_t p1, p2, p3;
    hx_u8 *b1 = hx_mempool_alloc(mp);
    hx_u8 *b2 = hx_mempool_alloc(mp);
    hx_u8 *b3 = hx_mempool_alloc(mp);
    memcpy(b1, "AAA", 3); p1 = (hx_pkt_t){ .data = b1, .len = 3, .buf_len = HX_MAX_PKT_SIZE };
    memcpy(b2, "BBB", 3); p2 = (hx_pkt_t){ .data = b2, .len = 3, .buf_len = HX_MAX_PKT_SIZE };
    memcpy(b3, "CCC", 3); p3 = (hx_pkt_t){ .data = b3, .len = 3, .buf_len = HX_MAX_PKT_SIZE };

    hx_pkt_t *tx1[1] = { &p1 };
    hx_pkt_t *tx2[1] = { &p2 };
    hx_pkt_t *tx3[1] = { &p3 };
    hx_pktio_tx_burst(&io, tx1, 1);
    hx_pktio_tx_burst(&io, tx2, 1);
    hx_pktio_tx_burst(&io, tx3, 1);

    /* FIFO: should come out in order */
    hx_pkt_t *rx[3];
    assert(hx_pktio_rx_burst(&io, rx, 3) == 3);
    assert(memcmp(rx[0]->data, "AAA", 3) == 0);
    assert(memcmp(rx[1]->data, "BBB", 3) == 0);
    assert(memcmp(rx[2]->data, "CCC", 3) == 0);

    hx_mempool_free(mp, b1);
    hx_mempool_free(mp, b2);
    hx_mempool_free(mp, b3);
    hx_pktio_close(&io);
    hx_mempool_destroy(mp);
    printf("  PASS: test_fifo_order\n");
}

int main(void)
{
    printf("test_pktio:\n");
    test_mock_init_close();
    test_tx_rx_single();
    test_tx_rx_burst();
    test_rx_empty();
    test_null_safety();
    test_fifo_order();
    printf("All pktio tests passed.\n");
    return 0;
}
