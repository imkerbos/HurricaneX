#include "hurricane/work_space.h"
#include "hurricane/log.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

#define HX_LOG_COMP_WS "work_space"

/* SYN retransmit parameters */
#define HX_SYN_RETRANSMIT_NS  1000000000ULL  /* 1 second in nanoseconds */
#define HX_SYN_MAX_RETRIES    3

/* --- Time helper ------------------------------------------------------- */

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static hx_u64 now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (hx_u64)ts.tv_sec * 1000000000ULL + (hx_u64)ts.tv_nsec;
}

/* --- ISN generation ---------------------------------------------------- */

static hx_u32 generate_isn(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    hx_u32 isn = (hx_u32)(ts.tv_nsec ^ (ts.tv_sec * 1000000));
    isn ^= (hx_u32)((uintptr_t)&ts >> 4);
    return isn;
}

/* --- TCP send via template --------------------------------------------- */

/*
 * Send a packet using a template. This is the hot path.
 * Allocates pkt from pktio, copies template, fills dynamic fields, pushes to TX queue.
 */
static hx_result_t ws_tcp_send(struct hx_work_space *ws,
                                struct hx_socket *sk,
                                struct hx_mbuf_cache *cache,
                                hx_u8 tcp_flags,
                                hx_u16 csum_tcp)
{
    hx_pkt_t *pkt = hx_ws_alloc_pkt_desc(ws);

    hx_result_t rc = hx_pktio_alloc_pkt(ws->pktio, pkt, HX_MAX_PKT_SIZE);
    if (rc != HX_OK)
        return rc;

    /* Copy template into packet buffer */
    memcpy(pkt->data, cache->tmpl.data, cache->tmpl.total_len);
    pkt->len = cache->tmpl.total_len;

    /* Fill dynamic fields */
    hx_tmpl_fill(cache, pkt->data,
                  sk->laddr, sk->faddr,
                  sk->lport, sk->fport,
                  hx_htonl(sk->snd_nxt), hx_htonl(sk->rcv_nxt),
                  tcp_flags,
                  hx_htons(ws->ip_id++),
                  sk->csum_ip,    /* TODO: incremental IP checksum */
                  csum_tcp);      /* TODO: incremental TCP checksum */

    /* For now, compute checksums properly (will optimize later) */
    hx_u8 *ip = pkt->data + cache->tmpl.l2_len;
    memset(ip + 10, 0, 2);
    hx_u16 ip_cksum = hx_ip_checksum(ip, HX_IPV4_HDR_LEN);
    memcpy(ip + 10, &ip_cksum, 2);

    hx_u8 *tcp = ip + cache->tmpl.l3_len;
    hx_u16 tcp_seg_len = cache->tmpl.l4_len + cache->tmpl.payload_len;
    memset(tcp + 16, 0, 2);
    hx_u16 tcp_cksum = hx_tcp_checksum(
        hx_ntohl(sk->laddr), hx_ntohl(sk->faddr),
        tcp, tcp_seg_len);
    memcpy(tcp + 16, &tcp_cksum, 2);

    hx_tx_queue_push(ws, pkt);
    return HX_OK;
}

/* Convenience wrappers */
static inline hx_result_t ws_send_syn(struct hx_work_space *ws,
                                       struct hx_socket *sk)
{
    return ws_tcp_send(ws, sk, &ws->tcp_syn, HX_TCP_FLAG_SYN,
                        sk->csum_tcp_opt);
}

static inline hx_result_t ws_send_ack(struct hx_work_space *ws,
                                       struct hx_socket *sk)
{
    return ws_tcp_send(ws, sk, &ws->tcp_ack, HX_TCP_FLAG_ACK,
                        sk->csum_tcp);
}

static inline hx_result_t ws_send_data(struct hx_work_space *ws,
                                        struct hx_socket *sk)
{
    return ws_tcp_send(ws, sk, &ws->tcp_data,
                        HX_TCP_FLAG_ACK | HX_TCP_FLAG_PSH,
                        sk->csum_tcp_data);
}

static inline hx_result_t ws_send_fin(struct hx_work_space *ws,
                                       struct hx_socket *sk)
{
    return ws_tcp_send(ws, sk, &ws->tcp_ack,
                        HX_TCP_FLAG_FIN | HX_TCP_FLAG_ACK,
                        sk->csum_tcp);
}

/* --- Client launch: create connections --------------------------------- */

static int ws_client_launch(struct hx_work_space *ws)
{
    hx_u32 batch = ws->cfg.launch_batch;
    if (batch == 0)
        batch = 64;

    int created = 0;
    hx_u64 ts = now_ns();

    for (hx_u32 i = 0; i < batch; i++) {
        struct hx_socket *sk = hx_socket_table_next(ws->st);
        if (!sk)
            break;

        sk->snd_nxt = generate_isn();
        sk->snd_una = sk->snd_nxt;
        sk->rcv_nxt = 0;
        sk->state = HX_SK_SYN_SENT;
        sk->retrans = 0;
        sk->timer_tsc = ts;
        sk->app_state = HX_APP_IDLE;
        sk->http_reqs = 0;

        hx_result_t rc = ws_send_syn(ws, sk);
        if (rc == HX_OK) {
            sk->snd_nxt++; /* SYN consumes 1 seq */
            ws->stats.conns_attempted++;
            created++;

            /* Debug: log first SYN */
            if (created == 1) {
                HX_LOG_WARN(HX_LOG_COMP_WS,
                    "first SYN: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u isn=%u",
                    (hx_ntohl(sk->laddr) >> 24) & 0xFF,
                    (hx_ntohl(sk->laddr) >> 16) & 0xFF,
                    (hx_ntohl(sk->laddr) >> 8) & 0xFF,
                    hx_ntohl(sk->laddr) & 0xFF,
                    hx_ntohs(sk->lport),
                    (hx_ntohl(sk->faddr) >> 24) & 0xFF,
                    (hx_ntohl(sk->faddr) >> 16) & 0xFF,
                    (hx_ntohl(sk->faddr) >> 8) & 0xFF,
                    hx_ntohl(sk->faddr) & 0xFF,
                    hx_ntohs(sk->fport),
                    sk->snd_nxt - 1);

                /* Hex dump first 58 bytes of the SYN packet */
                hx_pkt_t *last_pkt = ws->txq.buf[(ws->txq.tail - 1 + HX_TX_QUEUE_SIZE) % HX_TX_QUEUE_SIZE];
                if (last_pkt && last_pkt->data && last_pkt->len >= 54) {
                    char hex[180];
                    int off = 0;
                    hx_u32 dump_len = last_pkt->len < 58 ? last_pkt->len : 58;
                    for (hx_u32 b = 0; b < dump_len && off < 174; b++)
                        off += snprintf(hex + off, sizeof(hex) - off, "%02x ", last_pkt->data[b]);
                    HX_LOG_WARN(HX_LOG_COMP_WS, "SYN hex[%u]: %s", last_pkt->len, hex);
                }
            }
        } else {
            /* Back pressure — rewind pool index */
            ws->st->pool->next--;
            break;
        }
    }

    return created;
}

/* --- RX processing: TCP state machine ---------------------------------- */

static void ws_tcp_input(struct hx_work_space *ws,
                          struct hx_socket *sk,
                          const hx_u8 *tcp_seg, hx_u32 tcp_len)
{
    if (tcp_len < HX_TCP_HDR_LEN)
        return;

    /* Parse TCP header */
    hx_u8 flags;
    hx_u32 seq, ack_num;
    hx_u16 window;

    memcpy(&seq, tcp_seg + 4, 4);
    seq = hx_ntohl(seq);
    memcpy(&ack_num, tcp_seg + 8, 4);
    ack_num = hx_ntohl(ack_num);
    flags = tcp_seg[13];
    memcpy(&window, tcp_seg + 14, 2);
    (void)window;

    hx_u32 tcp_hdr_len = ((tcp_seg[12] >> 4) & 0x0F) * 4;
    const hx_u8 *payload = tcp_seg + tcp_hdr_len;
    hx_u32 payload_len = (tcp_len > tcp_hdr_len) ? tcp_len - tcp_hdr_len : 0;

    /* RST — any state */
    if (flags & HX_TCP_FLAG_RST) {
        sk->state = HX_SK_CLOSED;
        ws->stats.conns_reset++;
        return;
    }

    switch (sk->state) {
    case HX_SK_SYN_SENT:
        /* Expecting SYN+ACK */
        if ((flags & (HX_TCP_FLAG_SYN | HX_TCP_FLAG_ACK)) ==
            (HX_TCP_FLAG_SYN | HX_TCP_FLAG_ACK)) {
            if (ack_num != sk->snd_nxt)
                return; /* wrong ACK */

            sk->rcv_nxt = seq + 1;
            sk->snd_una = ack_num;
            sk->state = HX_SK_ESTABLISHED;
            ws->stats.conns_established++;

            /* Send ACK to complete handshake */
            ws_send_ack(ws, sk);

            /* If HTTP mode, send request immediately (dperf style) */
            if (ws->cfg.http_enabled && ws->http_req_len > 0) {
                ws_send_data(ws, sk);
                sk->snd_nxt += ws->http_req_len;
                sk->app_state = HX_APP_HTTP_RECV;
                ws->stats.http_req_sent++;
            }
        }
        break;

    case HX_SK_ESTABLISHED:
        if (flags & HX_TCP_FLAG_FIN) {
            sk->rcv_nxt = seq + payload_len + 1;
            ws_send_ack(ws, sk);
            sk->state = HX_SK_CLOSE_WAIT;
            /* Immediately send FIN back */
            ws_send_fin(ws, sk);
            sk->snd_nxt++;
            sk->state = HX_SK_LAST_ACK;
        } else if (flags & HX_TCP_FLAG_ACK) {
            if (ack_num > sk->snd_una)
                sk->snd_una = ack_num;

            if (payload_len > 0) {
                sk->rcv_nxt = seq + payload_len;
                ws_send_ack(ws, sk);

                /* HTTP response handling */
                if (ws->cfg.http_enabled &&
                    sk->app_state == HX_APP_HTTP_RECV) {
                    /* Scan for end of HTTP response (simple: look for \r\n\r\n) */
                    bool resp_done = false;
                    for (hx_u32 j = 0; j + 3 < payload_len; j++) {
                        if (payload[j] == '\r' && payload[j+1] == '\n' &&
                            payload[j+2] == '\r' && payload[j+3] == '\n') {
                            resp_done = true;
                            break;
                        }
                    }

                    if (resp_done) {
                        ws->stats.http_resp_recv++;

                        /* Parse status code */
                        if (payload_len >= 12 &&
                            payload[9] == '2' && payload[10] == '0')
                            ws->stats.http_resp_2xx++;
                        else
                            ws->stats.http_resp_other++;

                        sk->http_reqs++;

                        /* Keep-alive? */
                        hx_u32 limit = ws->cfg.http_requests_per_conn;
                        if (limit != 1 &&
                            (limit == 0 || sk->http_reqs < limit)) {
                            /* Send next request */
                            ws_send_data(ws, sk);
                            sk->snd_nxt += ws->http_req_len;
                            ws->stats.http_req_sent++;
                        } else {
                            /* Close connection */
                            sk->app_state = HX_APP_IDLE;
                            ws_send_fin(ws, sk);
                            sk->snd_nxt++;
                            sk->state = HX_SK_FIN_WAIT_1;
                        }
                    }
                }
            }
        }
        break;

    case HX_SK_FIN_WAIT_1:
        if ((flags & (HX_TCP_FLAG_FIN | HX_TCP_FLAG_ACK)) ==
            (HX_TCP_FLAG_FIN | HX_TCP_FLAG_ACK)) {
            sk->rcv_nxt = seq + 1;
            sk->snd_una = ack_num;
            ws_send_ack(ws, sk);
            sk->state = HX_SK_CLOSED;
            ws->stats.conns_closed++;
        } else if (flags & HX_TCP_FLAG_ACK) {
            sk->snd_una = ack_num;
            sk->state = HX_SK_FIN_WAIT_2;
        } else if (flags & HX_TCP_FLAG_FIN) {
            sk->rcv_nxt = seq + 1;
            ws_send_ack(ws, sk);
            sk->state = HX_SK_CLOSED;
            ws->stats.conns_closed++;
        }
        break;

    case HX_SK_FIN_WAIT_2:
        if (flags & HX_TCP_FLAG_FIN) {
            sk->rcv_nxt = seq + 1;
            ws_send_ack(ws, sk);
            sk->state = HX_SK_CLOSED;
            ws->stats.conns_closed++;
        }
        break;

    case HX_SK_LAST_ACK:
        if (flags & HX_TCP_FLAG_ACK) {
            sk->state = HX_SK_CLOSED;
            ws->stats.conns_closed++;
        }
        break;

    default:
        break;
    }
}

/* --- RX step ----------------------------------------------------------- */

int hx_ws_rx_step(struct hx_work_space *ws)
{
    hx_pkt_t *pkts[HX_MAX_BURST];
    int nb_rx = hx_pktio_rx_burst(ws->pktio, pkts, HX_MAX_BURST);

    for (int i = 0; i < nb_rx; i++) {
        hx_pkt_t *pkt = pkts[i];
        ws->stats.pkts_rx++;

        /* Parse L2 frame */
        hx_u32 src_ip, dst_ip;
        const hx_u8 *tcp_seg;
        hx_u32 tcp_len;

        hx_result_t rc = hx_net_parse_frame(pkt->data, pkt->len,
                                             &src_ip, &dst_ip,
                                             &tcp_seg, &tcp_len);
        if (rc != HX_OK || tcp_len < HX_TCP_HDR_LEN) {
            /* Debug: log non-TCP or malformed packets (first 20) */
            if (ws->stats.pkts_rx <= 20 && pkt->len >= 14) {
                hx_u16 etype;
                memcpy(&etype, pkt->data + 12, 2);
                HX_LOG_WARN(HX_LOG_COMP_WS,
                    "rx drop: len=%u etype=0x%04x rc=%d",
                    pkt->len, hx_ntohs(etype), rc);
            }
            hx_pktio_free_pkt(ws->pktio, pkt);
            continue;
        }

        /* Extract ports */
        hx_u16 tcp_sport, tcp_dport;
        memcpy(&tcp_sport, tcp_seg + 0, 2);
        memcpy(&tcp_dport, tcp_seg + 2, 2);

        /* Debug: log first 20 TCP packets */
        if (ws->stats.pkts_rx <= 20) {
            HX_LOG_WARN(HX_LOG_COMP_WS,
                "rx tcp: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u flags=0x%02x len=%u",
                (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                (src_ip >> 8) & 0xFF, src_ip & 0xFF,
                hx_ntohs(tcp_sport),
                (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
                (dst_ip >> 8) & 0xFF, dst_ip & 0xFF,
                hx_ntohs(tcp_dport),
                tcp_seg[13], tcp_len);
        }

        /* Lookup: frame's dst = our local, frame's src = foreign */
        struct hx_socket *sk = hx_socket_lookup(
            ws->st,
            hx_htonl(dst_ip), tcp_dport,   /* our local */
            hx_htonl(src_ip), tcp_sport);   /* foreign */

        if (!sk) {
            if (ws->stats.pkts_rx <= 20) {
                HX_LOG_WARN(HX_LOG_COMP_WS,
                    "rx lookup miss: local=%u.%u.%u.%u:%u foreign=%u.%u.%u.%u:%u "
                    "table: lport=%u..%u fport=%u..%u faddr=0x%08x..0x%08x",
                    (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
                    (dst_ip >> 8) & 0xFF, dst_ip & 0xFF,
                    hx_ntohs(tcp_dport),
                    (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                    (src_ip >> 8) & 0xFF, src_ip & 0xFF,
                    hx_ntohs(tcp_sport),
                    ws->st->lport_min, ws->st->lport_max,
                    ws->st->fport_min, ws->st->fport_max,
                    ws->st->faddr_min, ws->st->faddr_max);
            }
        } else {
            ws_tcp_input(ws, sk, tcp_seg, tcp_len);
        }

        hx_pktio_free_pkt(ws->pktio, pkt);
    }

    ws->stats.rx_loop_iters++;
    return nb_rx;
}

/* --- Retransmit step --------------------------------------------------- */

static void ws_retransmit_step(struct hx_work_space *ws, hx_u64 now)
{
    if (!ws->st || !ws->st->pool)
        return;

    int sent = 0;
    hx_u32 launched = ws->st->pool->next;

    for (hx_u32 i = 0; i < launched && sent < 32; i++) {
        struct hx_socket *sk = &ws->st->pool->sockets[i];
        if (sk->state != HX_SK_SYN_SENT)
            continue;

        if (now - sk->timer_tsc < HX_SYN_RETRANSMIT_NS)
            continue;

        if (sk->retrans >= HX_SYN_MAX_RETRIES) {
            sk->state = HX_SK_CLOSED;
            ws->stats.conns_failed++;
            continue;
        }

        /* Retransmit SYN with original ISN */
        sk->snd_nxt = sk->snd_una;
        hx_result_t rc = ws_send_syn(ws, sk);
        if (rc == HX_OK) {
            sk->snd_nxt = sk->snd_una + 1;
            sk->timer_tsc = now;
            sk->retrans++;
            ws->stats.conns_retransmit++;
            sent++;
        } else {
            sk->snd_nxt = sk->snd_una + 1;
            break;
        }
    }
}

/* --- Init -------------------------------------------------------------- */

hx_result_t hx_ws_init(struct hx_work_space *ws, hx_pktio_t *pktio,
                         const struct hx_ws_config *cfg)
{
    if (!ws || !pktio || !cfg || cfg->num_conns == 0)
        return HX_ERR_INVAL;

    memset(ws, 0, sizeof(*ws));
    ws->pktio = pktio;
    ws->cfg = *cfg;
    ws->running = false;
    ws->ip_id = 1;

    /* Create socket table */
    hx_u16 lport_max = cfg->src_port_base + (hx_u16)(cfg->num_conns - 1);
    ws->st = hx_socket_table_create(
        cfg->src_ip,
        cfg->src_port_base, lport_max,
        cfg->dst_ip, cfg->dst_ip,
        cfg->dst_port, cfg->dst_port);
    if (!ws->st)
        return HX_ERR_NOMEM;

    /* Build HTTP request if enabled */
    if (cfg->http_enabled) {
        hx_http_request_t req;
        hx_http_request_init(&req);
        req.method = cfg->http_method;
        if (cfg->http_host[0])
            snprintf(req.host, sizeof(req.host), "%s", cfg->http_host);
        if (cfg->http_path[0])
            snprintf(req.path, sizeof(req.path), "%s", cfg->http_path);
        if (cfg->http_extra_headers[0])
            snprintf(req.extra_headers, sizeof(req.extra_headers),
                     "%s", cfg->http_extra_headers);

        hx_http_build_request(&req, ws->http_req_buf,
                               sizeof(ws->http_req_buf), &ws->http_req_len);
    }

    /* Initialize packet templates */
    hx_mbuf_cache_init_tcp(&ws->tcp_syn, cfg->src_mac, cfg->dst_mac,
                            HX_TCP_FLAG_SYN, true, NULL, 0);

    hx_mbuf_cache_init_tcp(&ws->tcp_ack, cfg->src_mac, cfg->dst_mac,
                            HX_TCP_FLAG_ACK, false, NULL, 0);

    hx_mbuf_cache_init_tcp(&ws->tcp_data, cfg->src_mac, cfg->dst_mac,
                            HX_TCP_FLAG_ACK | HX_TCP_FLAG_PSH, false,
                            ws->http_req_buf, ws->http_req_len);

    HX_LOG_INFO(HX_LOG_COMP_WS,
                "work_space init: %u sockets, http=%s",
                ws->st->total_sockets,
                cfg->http_enabled ? "on" : "off");

    return HX_OK;
}

/* --- Main loop --------------------------------------------------------- */

hx_result_t hx_ws_run(struct hx_work_space *ws)
{
    if (!ws)
        return HX_ERR_INVAL;

    ws->running = true;
    double start = now_sec();
    double deadline = 0;
    if (ws->cfg.duration_sec > 0)
        deadline = start + (double)ws->cfg.duration_sec;

    hx_u64 last_retransmit = now_ns();

    HX_LOG_INFO(HX_LOG_COMP_WS,
                "main loop started: %u conns, duration %u sec",
                ws->cfg.num_conns, ws->cfg.duration_sec);

    while (ws->running) {
        /* 1. RX burst */
        hx_ws_rx_step(ws);

        /* 2. Launch new connections */
        hx_u32 launched = ws->st->pool ? ws->st->pool->next : 0;
        if (launched < ws->cfg.num_conns)
            ws_client_launch(ws);

        /* 3. RX again — pick up SYN-ACKs */
        hx_ws_rx_step(ws);

        /* 4. TX flush */
        hx_tx_queue_flush(ws);

        /* 5. Retransmit check (every ~0.5s) */
        hx_u64 now = now_ns();
        if (now - last_retransmit >= 500000000ULL) {
            ws_retransmit_step(ws, now);
            last_retransmit = now;
        }

        /* 6. Termination check */
        hx_u64 done;
        if (ws->cfg.http_enabled) {
            if (ws->cfg.http_requests_per_conn <= 1) {
                done = ws->stats.http_resp_recv +
                       ws->stats.conns_reset +
                       ws->stats.conns_failed;
            } else {
                done = ws->stats.conns_closed +
                       ws->stats.conns_reset +
                       ws->stats.conns_failed;
            }
        } else {
            done = ws->stats.conns_established +
                   ws->stats.conns_closed +
                   ws->stats.conns_reset +
                   ws->stats.conns_failed;
        }
        if (launched >= ws->cfg.num_conns && done >= ws->stats.conns_attempted)
            break;

        /* 7. Timeout */
        if (deadline > 0 && now_sec() >= deadline)
            break;
    }

    ws->stats.elapsed_sec = now_sec() - start;
    ws->running = false;
    return HX_OK;
}

/* --- Stop / Stats / Cleanup -------------------------------------------- */

void hx_ws_stop(struct hx_work_space *ws)
{
    if (ws)
        ws->running = false;
}

struct hx_ws_stats hx_ws_get_stats(const struct hx_work_space *ws)
{
    if (ws)
        return ws->stats;
    struct hx_ws_stats empty;
    memset(&empty, 0, sizeof(empty));
    return empty;
}

void hx_ws_cleanup(struct hx_work_space *ws)
{
    if (!ws)
        return;
    if (ws->st) {
        hx_socket_table_destroy(ws->st);
        ws->st = NULL;
    }
}
