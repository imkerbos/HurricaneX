#include "hurricane/tcp.h"
#include "hurricane/common.h"
#include "hurricane/mempool.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* --- Basic tests (unchanged) ------------------------------------------- */

static void test_state_str(void)
{
    assert(strcmp(hx_tcp_state_str(HX_TCP_CLOSED), "CLOSED") == 0);
    assert(strcmp(hx_tcp_state_str(HX_TCP_SYN_SENT), "SYN_SENT") == 0);
    assert(strcmp(hx_tcp_state_str(HX_TCP_ESTABLISHED), "ESTABLISHED") == 0);
    assert(strcmp(hx_tcp_state_str(HX_TCP_FIN_WAIT_1), "FIN_WAIT_1") == 0);
    assert(strcmp(hx_tcp_state_str(HX_TCP_FIN_WAIT_2), "FIN_WAIT_2") == 0);
    assert(strcmp(hx_tcp_state_str(HX_TCP_TIME_WAIT), "TIME_WAIT") == 0);
    assert(strcmp(hx_tcp_state_str(HX_TCP_CLOSE_WAIT), "CLOSE_WAIT") == 0);
    assert(strcmp(hx_tcp_state_str(HX_TCP_LAST_ACK), "LAST_ACK") == 0);
    assert(strcmp(hx_tcp_state_str((hx_tcp_state_t)99), "UNKNOWN") == 0);
    printf("  PASS: test_state_str\n");
}

static void test_init(void)
{
    hx_tcp_conn_t conn;
    assert(hx_tcp_init(&conn, NULL) == HX_OK);
    assert(conn.state == HX_TCP_CLOSED);
    assert(conn.rcv_wnd == 65535);
    assert(conn.snd_wnd == 65535);
    assert(hx_tcp_init(NULL, NULL) == HX_ERR_INVAL);
    printf("  PASS: test_init\n");
}

static void test_connect_no_pktio(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);

    hx_u32 dst_ip = 0x7F000001;
    assert(hx_tcp_connect(&conn, dst_ip, 80) == HX_OK);
    assert(conn.state == HX_TCP_SYN_SENT);
    assert(conn.dst_ip == dst_ip);
    assert(conn.dst_port == 80);
    assert(conn.snd_nxt != 0); /* ISN was generated */

    /* Connecting again from non-CLOSED state should fail */
    assert(hx_tcp_connect(&conn, dst_ip, 80) == HX_ERR_INVAL);

    printf("  PASS: test_connect_no_pktio\n");
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

    /* Manually set to ESTABLISHED — send should succeed (no pktio) */
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

static void test_close_from_close_wait(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_CLOSE_WAIT;

    assert(hx_tcp_close(&conn) == HX_OK);
    assert(conn.state == HX_TCP_LAST_ACK);

    printf("  PASS: test_close_from_close_wait\n");
}

/* --- Helper: build a fake TCP packet ----------------------------------- */

static hx_pkt_t *make_tcp_pkt(hx_u8 *buf, hx_u16 src_port, hx_u16 dst_port,
                                hx_u32 seq, hx_u32 ack, hx_u8 flags,
                                hx_u16 window,
                                const hx_u8 *payload, hx_u32 payload_len)
{
    static hx_pkt_t pkt;
    memset(buf, 0, HX_TCP_HDR_LEN);

    hx_tcp_hdr_t *hdr = (hx_tcp_hdr_t *)buf;
    hdr->src_port = src_port;
    hdr->dst_port = dst_port;
    hdr->seq      = seq;
    hdr->ack      = ack;
    hdr->data_off = (HX_TCP_HDR_LEN / 4) << 4;
    hdr->flags    = flags;
    hdr->window   = window;

    if (payload && payload_len > 0)
        memcpy(buf + HX_TCP_HDR_LEN, payload, payload_len);

    pkt.data = buf;
    pkt.len = HX_TCP_HDR_LEN + payload_len;
    pkt.buf_len = HX_MAX_PKT_SIZE;
    return &pkt;
}

/* --- State machine tests with packet I/O ------------------------------- */

static void test_three_way_handshake(void)
{
    hx_mempool_t *mp = hx_mempool_create("tcp_test", 128,
                                          HX_MAX_PKT_SIZE > sizeof(hx_pkt_t)
                                          ? HX_MAX_PKT_SIZE : sizeof(hx_pkt_t));
    assert(mp != NULL);

    hx_pktio_t io;
    assert(hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp) == HX_OK);

    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, &io);
    conn.src_port = 12345;

    /* Client sends SYN */
    assert(hx_tcp_connect(&conn, 0x7F000001, 80) == HX_OK);
    assert(conn.state == HX_TCP_SYN_SENT);

    /* Verify SYN packet was sent via pktio */
    hx_pkt_t *rx[1];
    assert(hx_pktio_rx_burst(&io, rx, 1) == 1);
    hx_tcp_hdr_t syn_hdr;
    memcpy(&syn_hdr, rx[0]->data, sizeof(syn_hdr));
    assert(syn_hdr.flags == HX_TCP_FLAG_SYN);
    hx_pktio_free_pkt(&io, rx[0]);

    /* Server responds with SYN+ACK */
    hx_u32 server_isn = 5000;
    hx_u8 pkt_buf[HX_MAX_PKT_SIZE];
    hx_pkt_t *syn_ack = make_tcp_pkt(pkt_buf, 80, 12345,
                                       server_isn, conn.snd_nxt,
                                       HX_TCP_FLAG_SYN | HX_TCP_FLAG_ACK,
                                       32768, NULL, 0);

    assert(hx_tcp_input(&conn, syn_ack) == HX_OK);
    assert(conn.state == HX_TCP_ESTABLISHED);
    assert(conn.rcv_nxt == server_isn + 1);
    assert(conn.snd_wnd == 32768);

    /* Verify ACK was sent to complete handshake */
    assert(hx_pktio_rx_burst(&io, rx, 1) == 1);
    hx_tcp_hdr_t ack_hdr;
    memcpy(&ack_hdr, rx[0]->data, sizeof(ack_hdr));
    assert(ack_hdr.flags == HX_TCP_FLAG_ACK);
    hx_pktio_free_pkt(&io, rx[0]);

    hx_pktio_close(&io);
    hx_mempool_destroy(mp);
    printf("  PASS: test_three_way_handshake\n");
}

static void test_data_transfer(void)
{
    hx_tcp_conn_t conn;
    hx_mempool_t *mp = hx_mempool_create("tcp_test", 128,
                                          HX_MAX_PKT_SIZE > sizeof(hx_pkt_t)
                                          ? HX_MAX_PKT_SIZE : sizeof(hx_pkt_t));
    hx_pktio_t io;
    hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp);
    hx_tcp_init(&conn, &io);
    conn.state = HX_TCP_ESTABLISHED;
    conn.snd_nxt = 1000;
    conn.rcv_nxt = 2000;
    conn.src_port = 12345;
    conn.dst_port = 80;

    /* Send data */
    const char *msg = "GET / HTTP/1.1\r\n\r\n";
    hx_u32 msg_len = (hx_u32)strlen(msg);
    assert(hx_tcp_send(&conn, (const hx_u8 *)msg, msg_len) == HX_OK);
    assert(conn.snd_nxt == 1000 + msg_len);

    /* Verify data packet was sent */
    hx_pkt_t *rx[1];
    assert(hx_pktio_rx_burst(&io, rx, 1) == 1);
    hx_tcp_hdr_t data_hdr;
    memcpy(&data_hdr, rx[0]->data, sizeof(data_hdr));
    assert(data_hdr.flags == (HX_TCP_FLAG_ACK | HX_TCP_FLAG_PSH));
    assert(rx[0]->len == HX_TCP_HDR_LEN + msg_len);

    /* Verify payload */
    assert(memcmp(rx[0]->data + HX_TCP_HDR_LEN, msg, msg_len) == 0);
    hx_pktio_free_pkt(&io, rx[0]);

    hx_pktio_close(&io);
    hx_mempool_destroy(mp);
    printf("  PASS: test_data_transfer\n");
}

static void test_receive_data_ack(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;
    conn.snd_nxt = 1000;
    conn.snd_una = 900;
    conn.rcv_nxt = 2000;

    /* Receive a data packet */
    hx_u8 pkt_buf[HX_MAX_PKT_SIZE];
    const char *payload = "hello";
    hx_pkt_t *pkt = make_tcp_pkt(pkt_buf, 80, 12345,
                                   2000, 1000,
                                   HX_TCP_FLAG_ACK, 65535,
                                   (const hx_u8 *)payload, 5);

    assert(hx_tcp_input(&conn, pkt) == HX_OK);
    assert(conn.state == HX_TCP_ESTABLISHED);
    assert(conn.rcv_nxt == 2005);
    assert(conn.snd_una == 1000);

    printf("  PASS: test_receive_data_ack\n");
}

static void test_rst_handling(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;

    hx_u8 pkt_buf[HX_MAX_PKT_SIZE];
    hx_pkt_t *rst = make_tcp_pkt(pkt_buf, 80, 12345,
                                   0, 0, HX_TCP_FLAG_RST, 0,
                                   NULL, 0);

    assert(hx_tcp_input(&conn, rst) == HX_ERR_CONNRESET);
    assert(conn.state == HX_TCP_CLOSED);

    printf("  PASS: test_rst_handling\n");
}

static void test_graceful_close(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;
    conn.snd_nxt = 1000;

    /* Client initiates close */
    assert(hx_tcp_close(&conn) == HX_OK);
    assert(conn.state == HX_TCP_FIN_WAIT_1);
    assert(conn.snd_nxt == 1001); /* FIN consumed 1 seq */

    /* Receive ACK for FIN */
    hx_u8 pkt_buf[HX_MAX_PKT_SIZE];
    hx_pkt_t *ack = make_tcp_pkt(pkt_buf, 80, 12345,
                                   3000, 1001,
                                   HX_TCP_FLAG_ACK, 65535,
                                   NULL, 0);
    assert(hx_tcp_input(&conn, ack) == HX_OK);
    assert(conn.state == HX_TCP_FIN_WAIT_2);

    /* Receive FIN from server */
    hx_pkt_t *fin = make_tcp_pkt(pkt_buf, 80, 12345,
                                   3000, 1001,
                                   HX_TCP_FLAG_FIN, 65535,
                                   NULL, 0);
    assert(hx_tcp_input(&conn, fin) == HX_OK);
    assert(conn.state == HX_TCP_TIME_WAIT);

    printf("  PASS: test_graceful_close\n");
}

static void test_passive_close(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;
    conn.rcv_nxt = 2000;

    /* Receive FIN from remote */
    hx_u8 pkt_buf[HX_MAX_PKT_SIZE];
    hx_pkt_t *fin = make_tcp_pkt(pkt_buf, 80, 12345,
                                   2000, 0,
                                   HX_TCP_FLAG_FIN, 65535,
                                   NULL, 0);
    assert(hx_tcp_input(&conn, fin) == HX_OK);
    assert(conn.state == HX_TCP_CLOSE_WAIT);

    /* Application closes */
    assert(hx_tcp_close(&conn) == HX_OK);
    assert(conn.state == HX_TCP_LAST_ACK);

    /* Receive final ACK */
    hx_pkt_t *last_ack = make_tcp_pkt(pkt_buf, 80, 12345,
                                        2001, conn.snd_nxt,
                                        HX_TCP_FLAG_ACK, 65535,
                                        NULL, 0);
    assert(hx_tcp_input(&conn, last_ack) == HX_OK);
    assert(conn.state == HX_TCP_CLOSED);

    printf("  PASS: test_passive_close\n");
}

static void test_simultaneous_close(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;
    conn.snd_nxt = 1000;

    /* Client sends FIN */
    assert(hx_tcp_close(&conn) == HX_OK);
    assert(conn.state == HX_TCP_FIN_WAIT_1);

    /* Receive FIN+ACK from server (simultaneous close) */
    hx_u8 pkt_buf[HX_MAX_PKT_SIZE];
    hx_pkt_t *fin_ack = make_tcp_pkt(pkt_buf, 80, 12345,
                                       3000, 1001,
                                       HX_TCP_FLAG_FIN | HX_TCP_FLAG_ACK,
                                       65535, NULL, 0);
    assert(hx_tcp_input(&conn, fin_ack) == HX_OK);
    assert(conn.state == HX_TCP_TIME_WAIT);

    printf("  PASS: test_simultaneous_close\n");
}

static void test_invalid_syn_ack(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    hx_tcp_connect(&conn, 0x7F000001, 80);
    assert(conn.state == HX_TCP_SYN_SENT);

    /* SYN+ACK with wrong ack number */
    hx_u8 pkt_buf[HX_MAX_PKT_SIZE];
    hx_pkt_t *bad_syn_ack = make_tcp_pkt(pkt_buf, 80, 12345,
                                           5000, 99999, /* wrong ack */
                                           HX_TCP_FLAG_SYN | HX_TCP_FLAG_ACK,
                                           65535, NULL, 0);
    assert(hx_tcp_input(&conn, bad_syn_ack) == HX_ERR_PROTO);
    assert(conn.state == HX_TCP_SYN_SENT); /* unchanged */

    printf("  PASS: test_invalid_syn_ack\n");
}

static void test_short_packet(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;

    /* Packet too short for TCP header */
    hx_u8 short_buf[10] = {0};
    hx_pkt_t short_pkt = { .data = short_buf, .len = 10, .buf_len = 10 };
    assert(hx_tcp_input(&conn, &short_pkt) == HX_ERR_PROTO);

    printf("  PASS: test_short_packet\n");
}

static void test_mock_pktio_loopback(void)
{
    hx_mempool_t *mp = hx_mempool_create("test_pkt", 64, HX_MAX_PKT_SIZE);
    assert(mp != NULL);

    hx_pktio_t io;
    assert(hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp) == HX_OK);

    hx_pkt_t pkt;
    hx_u8 *buf = hx_mempool_alloc(mp);
    assert(buf != NULL);
    memcpy(buf, "test-packet", 11);
    pkt.data = buf;
    pkt.len = 11;
    pkt.buf_len = HX_MAX_PKT_SIZE;

    hx_pkt_t *tx_pkts[1] = { &pkt };
    assert(hx_pktio_tx_burst(&io, tx_pkts, 1) == 1);

    hx_pkt_t *rx_pkts[1];
    assert(hx_pktio_rx_burst(&io, rx_pkts, 1) == 1);
    assert(rx_pkts[0] == &pkt);
    assert(memcmp(rx_pkts[0]->data, "test-packet", 11) == 0);

    hx_pktio_free_pkt(&io, rx_pkts[0]);
    hx_pktio_close(&io);
    hx_mempool_destroy(mp);

    printf("  PASS: test_mock_pktio_loopback\n");
}

int main(void)
{
    printf("test_tcp:\n");

    /* Basic tests */
    test_state_str();
    test_init();
    test_connect_no_pktio();
    test_send_requires_established();
    test_close_from_established();
    test_close_from_close_wait();

    /* State machine with packets */
    test_three_way_handshake();
    test_data_transfer();
    test_receive_data_ack();
    test_rst_handling();
    test_graceful_close();
    test_passive_close();
    test_simultaneous_close();
    test_invalid_syn_ack();
    test_short_packet();

    /* Pktio integration */
    test_mock_pktio_loopback();

    printf("All TCP tests passed.\n");
    return 0;
}
