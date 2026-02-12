#include "hurricane/engine.h"
#include "hurricane/log.h"
#include <string.h>
#include <time.h>

#define HX_LOG_COMP_ENGINE "engine"

/* SYN retransmit parameters */
#define HX_SYN_RETRANSMIT_SEC  1.0   /* retry after 1 second */
#define HX_SYN_MAX_RETRIES     3     /* give up after 3 retries */
#define HX_SYN_RETRANSMIT_BATCH 32   /* max retransmits per scan */

/* Default batch size: create this many connections per main-loop iteration */
#define HX_CONNECT_BATCH_DEFAULT 64

/* --- Time helpers ------------------------------------------------------ */

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* --- Init / Cleanup ---------------------------------------------------- */

hx_result_t hx_engine_init(hx_engine_t *eng, hx_pktio_t *pktio,
                            const hx_engine_config_t *cfg)
{
    if (!eng || !pktio || !cfg)
        return HX_ERR_INVAL;
    if (cfg->num_conns == 0)
        return HX_ERR_INVAL;

    memset(eng, 0, sizeof(*eng));
    eng->pktio = pktio;
    eng->cfg = *cfg;
    eng->running = false;
    eng->conn_create_idx = 0;
    eng->conn_create_batch = HX_CONNECT_BATCH_DEFAULT;

    /* Create connection table (2x capacity for headroom) */
    hx_u32 ct_cap = cfg->num_conns * 2;
    if (ct_cap < 64)
        ct_cap = 64;
    eng->ct = hx_conn_table_create(ct_cap);
    if (!eng->ct)
        return HX_ERR_NOMEM;

    return HX_OK;
}

void hx_engine_cleanup(hx_engine_t *eng)
{
    if (!eng)
        return;
    if (eng->ct) {
        hx_conn_table_destroy(eng->ct);
        eng->ct = NULL;
    }
}

/* --- Incremental connection creation ----------------------------------- */

int hx_engine_connect_step(hx_engine_t *eng)
{
    if (!eng || !eng->ct || !eng->pktio)
        return 0;

    const hx_engine_config_t *cfg = &eng->cfg;
    int created = 0;
    double ts = now_sec();

    hx_u32 end = eng->conn_create_idx + eng->conn_create_batch;
    if (end > cfg->num_conns)
        end = cfg->num_conns;

    hx_u32 i;
    for (i = eng->conn_create_idx; i < end; i++) {
        hx_u16 sport = cfg->src_port_base + (hx_u16)i;

        hx_tcp_conn_t *conn = hx_conn_table_insert(
            eng->ct,
            cfg->src_ip, sport,
            cfg->dst_ip, cfg->dst_port,
            eng->pktio,
            cfg->src_mac, cfg->dst_mac);

        if (!conn) {
            HX_LOG_WARN(HX_LOG_COMP_ENGINE,
                        "conn_table insert failed at conn %u", i);
            break;
        }

        hx_result_t rc = hx_tcp_connect(conn, cfg->dst_ip, cfg->dst_port);

        if (rc == HX_OK) {
            eng->stats.conns_attempted++;
            conn->last_send_ts = ts;
            conn->retries = 0;
            eng->stats.pkts_tx++;
            created++;
        } else if (rc == HX_ERR_AGAIN || rc == HX_ERR_NOMEM) {
            /*
             * TX ring full or mbuf exhaustion — back pressure.
             * Remove the half-initialized entry and stop this batch.
             * We'll retry from this index next iteration after RX
             * processing frees some mbufs.
             */
            hx_conn_table_remove(eng->ct,
                                  cfg->src_ip, sport,
                                  cfg->dst_ip, cfg->dst_port);
            break;
        } else {
            eng->stats.conns_attempted++;
            eng->stats.conns_failed++;
            HX_LOG_WARN(HX_LOG_COMP_ENGINE,
                        "tcp_connect failed for port %u: %s",
                        sport, hx_strerror(rc));
        }
    }

    eng->conn_create_idx = i;
    return created;
}

/* --- SYN retransmit ---------------------------------------------------- */

void hx_engine_retransmit_step(hx_engine_t *eng, double now)
{
    if (!eng || !eng->ct)
        return;

    hx_conn_table_t *ct = eng->ct;
    int sent = 0;

    for (hx_u32 i = 0; i < ct->capacity; i++) {
        hx_conn_slot_t *s = &ct->slots[i];
        if (s->state != HX_CONN_SLOT_USED)
            continue;

        hx_tcp_conn_t *conn = &s->conn;
        if (conn->state != HX_TCP_SYN_SENT)
            continue;

        /* Check if retransmit timeout elapsed */
        double elapsed = now - conn->last_send_ts;
        if (elapsed < HX_SYN_RETRANSMIT_SEC)
            continue;

        if (conn->retries >= HX_SYN_MAX_RETRIES) {
            /* Give up — mark as failed */
            conn->state = HX_TCP_CLOSED;
            eng->stats.conns_failed++;
            continue;
        }

        /* Rate-limit: stop if we've sent enough retransmits this scan */
        if (sent >= HX_SYN_RETRANSMIT_BATCH)
            break;

        /* Retransmit SYN with original ISN */
        hx_result_t rc = hx_tcp_retransmit_syn(conn);
        if (rc == HX_OK) {
            conn->last_send_ts = now;
            conn->retries++;
            eng->stats.conns_retransmit++;
            eng->stats.pkts_tx++;
            sent++;
        } else if (rc == HX_ERR_AGAIN || rc == HX_ERR_NOMEM) {
            /* TX ring full — stop retransmitting this round */
            break;
        }
    }
}

/* --- Start: prepare engine, don't burst all SYNs ----------------------- */

hx_result_t hx_engine_start(hx_engine_t *eng)
{
    if (!eng || !eng->ct || !eng->pktio)
        return HX_ERR_INVAL;

    eng->conn_create_idx = 0;
    eng->running = true;

    HX_LOG_INFO(HX_LOG_COMP_ENGINE,
                "engine started: %u conns planned, batch size %u",
                eng->cfg.num_conns, eng->conn_create_batch);

    return HX_OK;
}

/* --- RX step ----------------------------------------------------------- */

int hx_engine_rx_step(hx_engine_t *eng)
{
    if (!eng || !eng->pktio)
        return 0;

    hx_pkt_t *pkts[HX_MAX_BURST];
    int nb_rx = hx_pktio_rx_burst(eng->pktio, pkts, HX_MAX_BURST);

    for (int i = 0; i < nb_rx; i++) {
        hx_pkt_t *pkt = pkts[i];
        eng->stats.pkts_rx++;

        /* Parse L2 frame to extract IPs and TCP segment */
        hx_u32 src_ip, dst_ip;
        const hx_u8 *tcp_seg;
        hx_u32 tcp_len;

        hx_result_t rc = hx_net_parse_frame(pkt->data, pkt->len,
                                             &src_ip, &dst_ip,
                                             &tcp_seg, &tcp_len);
        if (rc != HX_OK || tcp_len < HX_TCP_HDR_LEN) {
            if (eng->stats.pkts_rx <= 5) {
                HX_LOG_WARN(HX_LOG_COMP_ENGINE,
                            "rx: parse_frame failed: rc=%d pkt_len=%u tcp_len=%u",
                            (int)rc, pkt->len, tcp_len);
            }
            hx_pktio_free_pkt(eng->pktio, pkt);
            continue;
        }

        /* Extract ports from TCP header (network byte order) */
        hx_u16 tcp_sport, tcp_dport;
        memcpy(&tcp_sport, tcp_seg + 0, 2);
        memcpy(&tcp_dport, tcp_seg + 2, 2);
        tcp_sport = hx_ntohs(tcp_sport);
        tcp_dport = hx_ntohs(tcp_dport);

        /*
         * Lookup connection: the frame's src is the remote side,
         * so we look up with swapped perspective:
         *   our conn's src_ip/src_port = frame's dst_ip/dst_port
         *   our conn's dst_ip/dst_port = frame's src_ip/src_port
         */
        hx_tcp_conn_t *conn = hx_conn_table_lookup(
            eng->ct, dst_ip, tcp_dport, src_ip, tcp_sport);

        if (!conn) {
            HX_LOG_WARN(HX_LOG_COMP_ENGINE,
                        "rx: no conn for %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u "
                        "(lookup: src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u) "
                        "ct_count=%u",
                        (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                        (src_ip >> 8) & 0xFF, src_ip & 0xFF, tcp_sport,
                        (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
                        (dst_ip >> 8) & 0xFF, dst_ip & 0xFF, tcp_dport,
                        (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
                        (dst_ip >> 8) & 0xFF, dst_ip & 0xFF, tcp_dport,
                        (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                        (src_ip >> 8) & 0xFF, src_ip & 0xFF, tcp_sport,
                        hx_conn_table_count(eng->ct));
            hx_pktio_free_pkt(eng->pktio, pkt);
            continue;
        }

        /* Feed TCP segment to state machine */
        hx_tcp_state_t prev_state = conn->state;

        hx_pkt_t tcp_pkt = {
            .data    = (hx_u8 *)tcp_seg,
            .len     = tcp_len,
            .buf_len = tcp_len,
            .opaque  = NULL,
        };
        rc = hx_tcp_input(conn, &tcp_pkt);

        /* Track state transitions */
        if (conn->state == HX_TCP_ESTABLISHED &&
            prev_state != HX_TCP_ESTABLISHED) {
            eng->stats.conns_established++;
        }
        if (conn->state == HX_TCP_CLOSED) {
            if (rc == HX_ERR_CONNRESET)
                eng->stats.conns_reset++;
            else
                eng->stats.conns_closed++;
        }

        /* Count TX packets generated by tcp_input (ACKs etc) */
        if (conn->state != prev_state)
            eng->stats.pkts_tx++;

        hx_pktio_free_pkt(eng->pktio, pkt);
    }

    eng->stats.rx_loop_iters++;
    return nb_rx;
}

/* --- Main loop --------------------------------------------------------- */

hx_result_t hx_engine_run(hx_engine_t *eng)
{
    if (!eng)
        return HX_ERR_INVAL;

    double start = now_sec();
    double deadline = 0;
    if (eng->cfg.duration_sec > 0)
        deadline = start + (double)eng->cfg.duration_sec;

    double last_retransmit = start;

    while (eng->running) {
        double now = now_sec();

        /* Phase 1: create connections incrementally */
        if (eng->conn_create_idx < eng->cfg.num_conns)
            hx_engine_connect_step(eng);

        /* Phase 2: process incoming packets */
        hx_engine_rx_step(eng);

        /* Phase 3: retransmit SYNs (check every 0.5s to avoid overhead) */
        if (now - last_retransmit >= 0.5) {
            hx_engine_retransmit_step(eng, now);
            last_retransmit = now;
        }

        /* Check termination: all connections resolved */
        hx_u64 done = eng->stats.conns_established +
                       eng->stats.conns_closed +
                       eng->stats.conns_reset +
                       eng->stats.conns_failed;
        if (eng->conn_create_idx >= eng->cfg.num_conns && done >= eng->stats.conns_attempted)
            break;

        /* Check timeout */
        if (deadline > 0 && now >= deadline)
            break;
    }

    eng->stats.elapsed_sec = now_sec() - start;
    eng->running = false;
    return HX_OK;
}

/* --- Stop / Stats ------------------------------------------------------ */

void hx_engine_stop(hx_engine_t *eng)
{
    if (eng)
        eng->running = false;
}

hx_engine_stats_t hx_engine_get_stats(const hx_engine_t *eng)
{
    if (eng)
        return eng->stats;
    hx_engine_stats_t empty;
    memset(&empty, 0, sizeof(empty));
    return empty;
}
