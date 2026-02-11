#include "hurricane/tcp.h"
#include "hurricane/mempool.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_state_str(void)
{
    assert(strcmp(hx_tcp_state_str(HX_TCP_CLOSED), "CLOSED") == 0);
    assert(strcmp(hx_tcp_state_str(HX_TCP_SYN_SENT), "SYN_SENT") == 0);
    assert(strcmp(hx_tcp_state_str(HX_TCP_ESTABLISHED), "ESTABLISHED") == 0);
    assert(strcmp(hx_tcp_state_str(HX_TCP_FIN_WAIT_1), "FIN_WAIT_1") == 0);
    printf("  PASS: test_state_str\n");
}

static void test_init(void)
{
    hx_tcp_conn_t conn;
    assert(hx_tcp_init(&conn, NULL) == HX_OK);
    assert(conn.state == HX_TCP_CLOSED);
    assert(conn.rcv_wnd == 65535);
    printf("  PASS: test_init\n");
}

static void test_connect(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);

    /* Connect should transition to SYN_SENT */
    hx_u32 dst_ip = 0x7F000001; /* 127.0.0.1 */
    assert(hx_tcp_connect(&conn, dst_ip, 80) == HX_OK);
    assert(conn.state == HX_TCP_SYN_SENT);
    assert(conn.dst_ip == dst_ip);
    assert(conn.dst_port == 80);

    /* Connecting again from non-CLOSED state should fail */
    assert(hx_tcp_connect(&conn, dst_ip, 80) == HX_ERR_INVAL);

    printf("  PASS: test_connect\n");
}

static void test_send_requires_established(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);

    hx_u8 data[] = "hello";

    /* Sending from CLOSED should fail */
    assert(hx_tcp_send(&conn, data, sizeof(data)) == HX_ERR_INVAL);

    /* Move to SYN_SENT — still should fail */
    hx_tcp_connect(&conn, 0x7F000001, 80);
    assert(hx_tcp_send(&conn, data, sizeof(data)) == HX_ERR_INVAL);

    /* Manually set to ESTABLISHED — send should succeed */
    conn.state = HX_TCP_ESTABLISHED;
    assert(hx_tcp_send(&conn, data, sizeof(data)) == HX_OK);

    printf("  PASS: test_send_requires_established\n");
}

static void test_close_from_established(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;

    assert(hx_tcp_close(&conn) == HX_OK);
    assert(conn.state == HX_TCP_FIN_WAIT_1);

    /* Closing again from FIN_WAIT_1 should fail */
    assert(hx_tcp_close(&conn) == HX_ERR_INVAL);

    printf("  PASS: test_close_from_established\n");
}

static void test_mock_pktio_loopback(void)
{
    hx_mempool_t *mp = hx_mempool_create("test_pkt", 64, HX_MAX_PKT_SIZE);
    assert(mp != NULL);

    hx_pktio_t io;
    assert(hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp) == HX_OK);

    /* Allocate a packet, fill it, transmit */
    hx_pkt_t pkt;
    hx_u8 *buf = hx_mempool_alloc(mp);
    assert(buf != NULL);
    memcpy(buf, "test-packet", 11);
    pkt.data = buf;
    pkt.len = 11;
    pkt.buf_len = HX_MAX_PKT_SIZE;

    hx_pkt_t *tx_pkts[1] = { &pkt };
    assert(hx_pktio_tx_burst(&io, tx_pkts, 1) == 1);

    /* Receive it back (mock loopback) */
    hx_pkt_t *rx_pkts[1];
    assert(hx_pktio_rx_burst(&io, rx_pkts, 1) == 1);
    assert(rx_pkts[0] == &pkt);
    assert(memcmp(rx_pkts[0]->data, "test-packet", 11) == 0);

    hx_mempool_free(mp, buf);
    hx_pktio_close(&io);
    hx_mempool_destroy(mp);

    printf("  PASS: test_mock_pktio_loopback\n");
}

int main(void)
{
    printf("test_tcp:\n");
    test_state_str();
    test_init();
    test_connect();
    test_send_requires_established();
    test_close_from_established();
    test_mock_pktio_loopback();
    printf("All TCP tests passed.\n");
    return 0;
}
