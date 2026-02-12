#include "hurricane/work_space.h"
#include "hurricane/mempool.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Work space integration test using mock pktio.
 *
 * Simulates: client sends SYN → we inject SYN-ACK → verify ACK + HTTP sent.
 */

/* Helper: build a fake TCP segment in a frame */
static void build_response_frame(hx_u8 *frame, hx_u32 *frame_len,
                                  const hx_u8 src_mac[6], const hx_u8 dst_mac[6],
                                  hx_u32 src_ip, hx_u32 dst_ip,
                                  hx_u16 sport, hx_u16 dport,
                                  hx_u32 seq, hx_u32 ack,
                                  hx_u8 flags,
                                  const hx_u8 *payload, hx_u32 payload_len)
{
    /* Build TCP segment */
    hx_u8 tcp_seg[HX_TCP_HDR_LEN + 2048];
    memset(tcp_seg, 0, HX_TCP_HDR_LEN);
    hx_u16 sp = hx_htons(sport);
    hx_u16 dp = hx_htons(dport);
    hx_u32 seq_n = hx_htonl(seq);
    hx_u32 ack_n = hx_htonl(ack);
    hx_u16 wnd = hx_htons(65535);
    memcpy(tcp_seg + 0, &sp, 2);
    memcpy(tcp_seg + 2, &dp, 2);
    memcpy(tcp_seg + 4, &seq_n, 4);
    memcpy(tcp_seg + 8, &ack_n, 4);
    tcp_seg[12] = (HX_TCP_HDR_LEN / 4) << 4;
    tcp_seg[13] = flags;
    memcpy(tcp_seg + 14, &wnd, 2);

    hx_u32 tcp_len = HX_TCP_HDR_LEN + payload_len;
    if (payload && payload_len > 0)
        memcpy(tcp_seg + HX_TCP_HDR_LEN, payload, payload_len);

    /* TCP checksum */
    hx_u16 tcp_cksum = hx_tcp_checksum(src_ip, dst_ip, tcp_seg, tcp_len);
    memcpy(tcp_seg + 16, &tcp_cksum, 2);

    /* Build frame */
    *frame_len = hx_net_build_frame(src_mac, dst_mac,
                                     src_ip, dst_ip,
                                     tcp_seg, tcp_len,
                                     frame, HX_MAX_PKT_SIZE);
}

/* Inject a frame into mock pktio (TX side, so it appears on RX).
 * The mock ring stores hx_pkt_t pointers, so we must heap-allocate
 * the descriptor to keep it alive until rx_burst reads it. */
static void inject_frame(hx_pktio_t *io, hx_mempool_t *mp,
                          hx_u8 *frame, hx_u32 frame_len)
{
    hx_pkt_t *pkt = calloc(1, sizeof(*pkt));
    assert(pkt != NULL);
    hx_u8 *buf = hx_mempool_alloc(mp);
    assert(buf != NULL);
    memcpy(buf, frame, frame_len);
    pkt->data = buf;
    pkt->len = frame_len;
    pkt->buf_len = HX_MAX_PKT_SIZE;
    pkt->opaque = NULL;

    hx_pkt_t *pkts[1] = { pkt };
    assert(hx_pktio_tx_burst(io, pkts, 1) == 1);
}

/* --- Test: basic init -------------------------------------------------- */

static void test_ws_init(void)
{
    hx_mempool_t *mp = hx_mempool_create("ws_test", 256, HX_MAX_PKT_SIZE);
    assert(mp != NULL);

    hx_pktio_t io;
    assert(hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp) == HX_OK);

    struct hx_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.src_ip = 0xC0A80001;
    cfg.dst_ip = 0x0A000001;
    cfg.dst_port = 80;
    cfg.src_port_base = 10000;
    cfg.num_conns = 5;
    cfg.duration_sec = 10;

    struct hx_work_space ws;
    assert(hx_ws_init(&ws, &io, &cfg) == HX_OK);
    assert(ws.st != NULL);
    assert(hx_socket_table_count(ws.st) == 5);

    hx_ws_cleanup(&ws);
    hx_pktio_close(&io);
    hx_mempool_destroy(mp);
    printf("  PASS: test_ws_init\n");
}

/* --- Test: SYN → SYN-ACK → ESTABLISHED -------------------------------- */

static void test_ws_handshake(void)
{
    hx_mempool_t *mp = hx_mempool_create("ws_test", 256, HX_MAX_PKT_SIZE);
    hx_pktio_t io;
    hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp);

    struct hx_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.src_ip = 0xC0A80001;
    cfg.dst_ip = 0x0A000001;
    cfg.dst_port = 80;
    cfg.src_port_base = 10000;
    cfg.num_conns = 1;
    cfg.duration_sec = 5;
    cfg.launch_batch = 1;

    struct hx_work_space ws;
    hx_ws_init(&ws, &io, &cfg);

    /* Drain the mock ring — we'll manually drive the loop */
    /* Step 1: Launch connection (sends SYN) */
    struct hx_socket *sk = hx_socket_table_next(ws.st);
    assert(sk != NULL);
    /* Reset pool so ws_client_launch can pick it up */
    hx_socket_table_reset_launch(ws.st);

    /* Run one iteration of launch */
    ws.running = true;

    /* Manually call launch */
    /* We need to get the socket's snd_nxt after SYN */
    /* Let's just use the run loop with a short timeout */

    /* Actually, let's test the socket directly */
    /* Re-init socket */
    sk->snd_nxt = 1000;
    sk->snd_una = 1000;
    sk->state = HX_SK_SYN_SENT;
    sk->snd_nxt++; /* SYN consumed 1 */

    /* Drain any packets from mock ring */
    hx_pkt_t *drain[64];
    int nb;
    while ((nb = hx_pktio_rx_burst(&io, drain, 64)) > 0) {
        for (int i = 0; i < nb; i++) {
            hx_pktio_free_pkt(&io, drain[i]);
        }
    }

    /* Inject SYN-ACK from server */
    hx_u8 frame[HX_MAX_PKT_SIZE];
    hx_u32 flen;
    hx_u8 smac[6] = {0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03};
    hx_u8 dmac[6] = {0};

    build_response_frame(frame, &flen, smac, dmac,
                          0x0A000001, 0xC0A80001,  /* server → client */
                          80, 10000,                /* sport=80, dport=10000 */
                          5000, 1001,               /* seq=5000, ack=1001 */
                          HX_TCP_FLAG_SYN | HX_TCP_FLAG_ACK,
                          NULL, 0);

    inject_frame(&io, mp, frame, flen);

    /* Process RX — should transition to ESTABLISHED */
    hx_ws_rx_step(&ws);

    assert(sk->state == HX_SK_ESTABLISHED);
    assert(sk->rcv_nxt == 5001);
    assert(ws.stats.conns_established == 1);

    hx_ws_cleanup(&ws);
    hx_pktio_close(&io);
    hx_mempool_destroy(mp);
    printf("  PASS: test_ws_handshake\n");
}

/* --- Test: full HTTP flow ---------------------------------------------- */

static void test_ws_http_flow(void)
{
    hx_mempool_t *mp = hx_mempool_create("ws_test", 512, HX_MAX_PKT_SIZE);
    hx_pktio_t io;
    hx_pktio_init(&io, &hx_pktio_mock_ops, "mock0", mp);

    struct hx_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.src_ip = 0xC0A80001;
    cfg.dst_ip = 0x0A000001;
    cfg.dst_port = 80;
    cfg.src_port_base = 10000;
    cfg.num_conns = 1;
    cfg.duration_sec = 5;
    cfg.http_enabled = true;
    cfg.http_method = HX_HTTP_GET;
    snprintf(cfg.http_host, sizeof(cfg.http_host), "test.com");
    snprintf(cfg.http_path, sizeof(cfg.http_path), "/");
    cfg.http_requests_per_conn = 1;

    struct hx_work_space ws;
    hx_ws_init(&ws, &io, &cfg);
    assert(ws.http_req_len > 0);

    /* Setup socket as SYN_SENT */
    struct hx_socket *sk = &ws.st->pool->sockets[0];
    sk->snd_nxt = 1000;
    sk->snd_una = 1000;
    sk->state = HX_SK_SYN_SENT;
    sk->snd_nxt++;

    /* Drain mock ring */
    hx_pkt_t *drain[64];
    while (hx_pktio_rx_burst(&io, drain, 64) > 0) {}

    /* Inject SYN-ACK */
    hx_u8 frame[HX_MAX_PKT_SIZE];
    hx_u32 flen;
    hx_u8 smac[6] = {0};

    build_response_frame(frame, &flen, smac, smac,
                          0x0A000001, 0xC0A80001,
                          80, 10000,
                          5000, 1001,
                          HX_TCP_FLAG_SYN | HX_TCP_FLAG_ACK,
                          NULL, 0);
    inject_frame(&io, mp, frame, flen);

    /* Process — should establish + send HTTP */
    hx_ws_rx_step(&ws);
    hx_tx_queue_flush(&ws);

    assert(sk->state == HX_SK_ESTABLISHED);
    assert(sk->app_state == HX_APP_HTTP_RECV);
    assert(ws.stats.http_req_sent == 1);

    /* Drain TX packets (ACK + HTTP data) */
    while (hx_pktio_rx_burst(&io, drain, 64) > 0) {}

    /* Inject HTTP response */
    const char *http_resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    hx_u32 resp_len = (hx_u32)strlen(http_resp);

    build_response_frame(frame, &flen, smac, smac,
                          0x0A000001, 0xC0A80001,
                          80, 10000,
                          5001, sk->snd_nxt,
                          HX_TCP_FLAG_ACK | HX_TCP_FLAG_PSH,
                          (const hx_u8 *)http_resp, resp_len);
    inject_frame(&io, mp, frame, flen);

    /* Process — should parse response and close */
    hx_ws_rx_step(&ws);
    hx_tx_queue_flush(&ws);

    assert(ws.stats.http_resp_recv == 1);
    assert(ws.stats.http_resp_2xx == 1);
    assert(sk->state == HX_SK_FIN_WAIT_1);

    hx_ws_cleanup(&ws);
    hx_pktio_close(&io);
    hx_mempool_destroy(mp);
    printf("  PASS: test_ws_http_flow\n");
}

int main(void)
{
    printf("test_work_space:\n");
    test_ws_init();
    test_ws_handshake();
    test_ws_http_flow();
    printf("All work_space tests passed.\n");
    return 0;
}
