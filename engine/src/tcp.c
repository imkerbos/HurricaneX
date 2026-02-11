#include "hurricane/tcp.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Custom TCP state machine for high-performance connection simulation.
 *
 * Builds raw TCP segments (no IP/Ethernet framing — that's pktio's job)
 * and drives state transitions based on incoming packet flags.
 */

/* --- ISN generation ---------------------------------------------------- */

static hx_u32 hx_tcp_generate_isn(void)
{
    /*
     * Simple ISN: time-based + random component.
     * In production DPDK path this would use rte_rdtsc() for speed.
     */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    hx_u32 isn = (hx_u32)(ts.tv_nsec ^ (ts.tv_sec * 1000000));
    isn ^= (hx_u32)((uintptr_t)&ts >> 4); /* ASLR entropy */
    return isn;
}

/* --- Packet construction helpers --------------------------------------- */

/*
 * Build a TCP segment into a pkt buffer.
 * Writes the 20-byte TCP header followed by optional payload.
 * Returns total segment length, or 0 on error.
 */
static hx_u32 hx_tcp_build_segment(const hx_tcp_conn_t *conn,
                                     hx_u8 flags,
                                     const hx_u8 *payload,
                                     hx_u32 payload_len,
                                     hx_u8 *buf, hx_u32 buf_size)
{
    hx_u32 total = HX_TCP_HDR_LEN + payload_len;
    if (total > buf_size)
        return 0;

    memset(buf, 0, HX_TCP_HDR_LEN);

    /* Write header fields via memcpy to avoid alignment issues */
    hx_tcp_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.src_port = conn->src_port;
    hdr.dst_port = conn->dst_port;
    hdr.seq      = conn->snd_nxt;
    hdr.ack      = conn->rcv_nxt;
    hdr.data_off = (HX_TCP_HDR_LEN / 4) << 4; /* 5 words, no options */
    hdr.flags    = flags;
    hdr.window   = conn->rcv_wnd;
    hdr.checksum = 0; /* offloaded or computed later */
    hdr.urgent   = 0;
    memcpy(buf, &hdr, HX_TCP_HDR_LEN);

    if (payload && payload_len > 0)
        memcpy(buf + HX_TCP_HDR_LEN, payload, payload_len);

    return total;
}

/*
 * Send a TCP segment through pktio.
 * Allocates a pkt from the mempool, builds the segment, and transmits.
 */
/*
 * Small ring of pkt descriptors for outgoing segments.
 * Avoids heap allocation for hx_pkt_t while keeping pointers valid
 * for the mock pktio ring buffer.
 */
#define HX_TCP_PKT_RING_SIZE 64
static hx_pkt_t g_pkt_ring[HX_TCP_PKT_RING_SIZE];
static int g_pkt_ring_idx = 0;

static hx_pkt_t *hx_tcp_alloc_pkt_desc(void)
{
    hx_pkt_t *p = &g_pkt_ring[g_pkt_ring_idx];
    g_pkt_ring_idx = (g_pkt_ring_idx + 1) % HX_TCP_PKT_RING_SIZE;
    return p;
}

static hx_result_t hx_tcp_send_segment(hx_tcp_conn_t *conn,
                                         hx_u8 flags,
                                         const hx_u8 *payload,
                                         hx_u32 payload_len)
{
    if (!conn->pktio || !conn->pktio->mp)
        return HX_ERR_INVAL;

    hx_u8 *buf = hx_mempool_alloc(conn->pktio->mp);
    if (!buf)
        return HX_ERR_NOMEM;

    hx_u32 seg_len = hx_tcp_build_segment(conn, flags, payload, payload_len,
                                            buf, HX_MAX_PKT_SIZE);
    if (seg_len == 0) {
        hx_mempool_free(conn->pktio->mp, buf);
        return HX_ERR_NOMEM;
    }

    hx_pkt_t *pkt = hx_tcp_alloc_pkt_desc();
    pkt->data = buf;
    pkt->len = seg_len;
    pkt->buf_len = HX_MAX_PKT_SIZE;

    hx_pkt_t *pkts[1] = { pkt };
    int sent = hx_pktio_tx_burst(conn->pktio, pkts, 1);
    if (sent != 1) {
        hx_mempool_free(conn->pktio->mp, buf);
        return HX_ERR_AGAIN;
    }

    return HX_OK;
}

/* --- Parse incoming TCP header ----------------------------------------- */

static hx_result_t hx_tcp_parse_header(const hx_pkt_t *pkt,
                                         hx_tcp_hdr_t *hdr,
                                         const hx_u8 **payload,
                                         hx_u32 *payload_len)
{
    if (pkt->len < HX_TCP_HDR_LEN)
        return HX_ERR_PROTO;

    memcpy(hdr, pkt->data, HX_TCP_HDR_LEN);

    hx_u32 hdr_len = ((hdr->data_off >> 4) & 0x0F) * 4;
    if (hdr_len < HX_TCP_HDR_LEN || hdr_len > pkt->len)
        return HX_ERR_PROTO;

    *payload = pkt->data + hdr_len;
    *payload_len = pkt->len - hdr_len;

    return HX_OK;
}

/* --- Public API -------------------------------------------------------- */

const char *hx_tcp_state_str(hx_tcp_state_t state)
{
    switch (state) {
    case HX_TCP_CLOSED:      return "CLOSED";
    case HX_TCP_SYN_SENT:    return "SYN_SENT";
    case HX_TCP_ESTABLISHED: return "ESTABLISHED";
    case HX_TCP_FIN_WAIT_1:  return "FIN_WAIT_1";
    case HX_TCP_FIN_WAIT_2:  return "FIN_WAIT_2";
    case HX_TCP_TIME_WAIT:   return "TIME_WAIT";
    case HX_TCP_CLOSE_WAIT:  return "CLOSE_WAIT";
    case HX_TCP_LAST_ACK:    return "LAST_ACK";
    default:                 return "UNKNOWN";
    }
}

hx_result_t hx_tcp_init(hx_tcp_conn_t *conn, hx_pktio_t *pktio)
{
    if (!conn)
        return HX_ERR_INVAL;

    memset(conn, 0, sizeof(*conn));
    conn->state = HX_TCP_CLOSED;
    conn->pktio = pktio;
    conn->rcv_wnd = 65535;
    conn->snd_wnd = 65535;

    return HX_OK;
}

hx_result_t hx_tcp_connect(hx_tcp_conn_t *conn,
                            hx_u32 dst_ip, hx_u16 dst_port)
{
    if (!conn)
        return HX_ERR_INVAL;
    if (conn->state != HX_TCP_CLOSED)
        return HX_ERR_INVAL;

    conn->dst_ip = dst_ip;
    conn->dst_port = dst_port;

    /* Generate ISN */
    conn->snd_nxt = hx_tcp_generate_isn();
    conn->snd_una = conn->snd_nxt;

    /* Send SYN */
    if (conn->pktio) {
        hx_result_t rc = hx_tcp_send_segment(conn, HX_TCP_FLAG_SYN, NULL, 0);
        if (rc != HX_OK)
            return rc;
    }

    /* SYN consumes one sequence number */
    conn->snd_nxt++;
    conn->state = HX_TCP_SYN_SENT;
    return HX_OK;
}

hx_result_t hx_tcp_send(hx_tcp_conn_t *conn,
                         const hx_u8 *data, hx_u32 len)
{
    if (!conn || !data)
        return HX_ERR_INVAL;
    if (conn->state != HX_TCP_ESTABLISHED)
        return HX_ERR_INVAL;

    /* Segment data into MSS-sized chunks */
    hx_u32 mss = HX_MAX_PKT_SIZE - HX_TCP_HDR_LEN;
    hx_u32 offset = 0;

    while (offset < len) {
        hx_u32 chunk = len - offset;
        if (chunk > mss)
            chunk = mss;

        hx_u8 flags = HX_TCP_FLAG_ACK;
        if (offset + chunk >= len)
            flags |= HX_TCP_FLAG_PSH; /* push on last segment */

        if (conn->pktio) {
            hx_result_t rc = hx_tcp_send_segment(conn, flags,
                                                   data + offset, chunk);
            if (rc != HX_OK)
                return rc;
        }

        conn->snd_nxt += chunk;
        offset += chunk;
    }

    return HX_OK;
}

hx_result_t hx_tcp_input(hx_tcp_conn_t *conn, const hx_pkt_t *pkt)
{
    if (!conn || !pkt)
        return HX_ERR_INVAL;

    hx_tcp_hdr_t hdr;
    const hx_u8 *payload = NULL;
    hx_u32 payload_len = 0;

    hx_result_t rc = hx_tcp_parse_header(pkt, &hdr, &payload, &payload_len);
    if (rc != HX_OK)
        return rc;

    hx_u8 flags = hdr.flags;

    /* RST handling — any state */
    if (flags & HX_TCP_FLAG_RST) {
        conn->state = HX_TCP_CLOSED;
        return HX_ERR_CONNRESET;
    }

    switch (conn->state) {
    case HX_TCP_SYN_SENT:
        /* Expecting SYN+ACK */
        if ((flags & (HX_TCP_FLAG_SYN | HX_TCP_FLAG_ACK)) ==
            (HX_TCP_FLAG_SYN | HX_TCP_FLAG_ACK)) {
            /* Validate ACK number */
            if (hdr.ack != conn->snd_nxt)
                return HX_ERR_PROTO;

            conn->rcv_nxt = hdr.seq + 1; /* SYN consumes 1 seq */
            conn->snd_una = hdr.ack;
            conn->snd_wnd = hdr.window;

            /* Send ACK to complete handshake */
            if (conn->pktio)
                hx_tcp_send_segment(conn, HX_TCP_FLAG_ACK, NULL, 0);

            conn->state = HX_TCP_ESTABLISHED;
        }
        break;

    case HX_TCP_ESTABLISHED:
        if (flags & HX_TCP_FLAG_FIN) {
            conn->rcv_nxt = hdr.seq + payload_len + 1; /* FIN consumes 1 */

            /* Send ACK for FIN */
            if (conn->pktio)
                hx_tcp_send_segment(conn, HX_TCP_FLAG_ACK, NULL, 0);

            conn->state = HX_TCP_CLOSE_WAIT;
        } else if (flags & HX_TCP_FLAG_ACK) {
            /* Update send window */
            if (hdr.ack > conn->snd_una)
                conn->snd_una = hdr.ack;
            conn->snd_wnd = hdr.window;

            /* Advance receive sequence for payload */
            if (payload_len > 0) {
                conn->rcv_nxt = hdr.seq + payload_len;

                /* Send ACK */
                if (conn->pktio)
                    hx_tcp_send_segment(conn, HX_TCP_FLAG_ACK, NULL, 0);
            }
        }
        break;

    case HX_TCP_FIN_WAIT_1:
        if ((flags & (HX_TCP_FLAG_FIN | HX_TCP_FLAG_ACK)) ==
            (HX_TCP_FLAG_FIN | HX_TCP_FLAG_ACK)) {
            /* Simultaneous close: FIN+ACK */
            conn->rcv_nxt = hdr.seq + 1;
            conn->snd_una = hdr.ack;

            if (conn->pktio)
                hx_tcp_send_segment(conn, HX_TCP_FLAG_ACK, NULL, 0);

            conn->state = HX_TCP_TIME_WAIT;
        } else if (flags & HX_TCP_FLAG_ACK) {
            conn->snd_una = hdr.ack;
            conn->state = HX_TCP_FIN_WAIT_2;
        } else if (flags & HX_TCP_FLAG_FIN) {
            conn->rcv_nxt = hdr.seq + 1;

            if (conn->pktio)
                hx_tcp_send_segment(conn, HX_TCP_FLAG_ACK, NULL, 0);

            conn->state = HX_TCP_TIME_WAIT;
        }
        break;

    case HX_TCP_FIN_WAIT_2:
        if (flags & HX_TCP_FLAG_FIN) {
            conn->rcv_nxt = hdr.seq + 1;

            if (conn->pktio)
                hx_tcp_send_segment(conn, HX_TCP_FLAG_ACK, NULL, 0);

            conn->state = HX_TCP_TIME_WAIT;
        }
        break;

    case HX_TCP_CLOSE_WAIT:
        /* Waiting for application to call close */
        break;

    case HX_TCP_LAST_ACK:
        if (flags & HX_TCP_FLAG_ACK) {
            conn->snd_una = hdr.ack;
            conn->state = HX_TCP_CLOSED;
        }
        break;

    case HX_TCP_TIME_WAIT:
        /* In real impl, wait 2*MSL then transition to CLOSED.
         * For simulation, immediately close. */
        conn->state = HX_TCP_CLOSED;
        break;

    default:
        break;
    }

    return HX_OK;
}

hx_result_t hx_tcp_close(hx_tcp_conn_t *conn)
{
    if (!conn)
        return HX_ERR_INVAL;

    switch (conn->state) {
    case HX_TCP_ESTABLISHED:
        /* Send FIN */
        if (conn->pktio)
            hx_tcp_send_segment(conn, HX_TCP_FLAG_FIN | HX_TCP_FLAG_ACK,
                                NULL, 0);
        conn->snd_nxt++; /* FIN consumes 1 seq */
        conn->state = HX_TCP_FIN_WAIT_1;
        return HX_OK;

    case HX_TCP_CLOSE_WAIT:
        /* Send FIN */
        if (conn->pktio)
            hx_tcp_send_segment(conn, HX_TCP_FLAG_FIN | HX_TCP_FLAG_ACK,
                                NULL, 0);
        conn->snd_nxt++;
        conn->state = HX_TCP_LAST_ACK;
        return HX_OK;

    default:
        return HX_ERR_INVAL;
    }
}
