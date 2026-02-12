#include "hurricane/tcp.h"
#include "hurricane/net.h"
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

/*
 * Send a TCP segment — builds Eth+IP+TCP+payload directly into pkt->data
 * in a single pass, no intermediate buffer or extra memcpy.
 */
static hx_result_t hx_tcp_send_segment(hx_tcp_conn_t *conn,
                                         hx_u8 flags,
                                         const hx_u8 *payload,
                                         hx_u32 payload_len)
{
    if (!conn->pktio)
        return HX_ERR_INVAL;

    hx_u32 tcp_seg_len = HX_TCP_HDR_LEN + payload_len;
    hx_u32 frame_len   = HX_FRAME_HDR_LEN + tcp_seg_len;

    hx_pkt_t *pkt = hx_tcp_alloc_pkt_desc();

    hx_result_t rc = hx_pktio_alloc_pkt(conn->pktio, pkt, HX_MAX_PKT_SIZE);
    if (rc != HX_OK)
        return rc;

    if (frame_len > pkt->buf_len) {
        hx_pktio_free_pkt(conn->pktio, pkt);
        return HX_ERR_NOMEM;
    }

    hx_u8 *buf = pkt->data;

    /* --- Ethernet header (14 bytes) --- */
    memcpy(buf + 0, conn->dst_mac, 6);
    memcpy(buf + 6, conn->src_mac, 6);
    hx_u16 etype = hx_htons(HX_ETHER_TYPE_IPV4);
    memcpy(buf + 12, &etype, 2);

    /* --- IPv4 header (20 bytes) --- */
    hx_u8 *ip = buf + HX_ETHER_HDR_LEN;
    memset(ip, 0, HX_IPV4_HDR_LEN);
    ip[0] = 0x45;                                       /* ver=4, ihl=5 */
    hx_u16 ip_total = hx_htons((hx_u16)(HX_IPV4_HDR_LEN + tcp_seg_len));
    memcpy(ip + 2, &ip_total, 2);                       /* total_len */
    ip[8] = HX_IP_DEFAULT_TTL;                           /* TTL */
    ip[9] = HX_IP_PROTO_TCP;                             /* protocol */
    hx_u32 src_n = hx_htonl(conn->src_ip);
    hx_u32 dst_n = hx_htonl(conn->dst_ip);
    memcpy(ip + 12, &src_n, 4);                          /* src_ip */
    memcpy(ip + 16, &dst_n, 4);                          /* dst_ip */
    /* IP checksum (header only, 20 bytes) */
    hx_u16 ip_cksum = hx_ip_checksum(ip, HX_IPV4_HDR_LEN);
    memcpy(ip + 10, &ip_cksum, 2);

    /* --- TCP header (20 bytes) + payload --- */
    hx_u8 *tcp = buf + HX_FRAME_HDR_LEN;
    memset(tcp, 0, HX_TCP_HDR_LEN);
    hx_u16 sp = hx_htons(conn->src_port);
    hx_u16 dp = hx_htons(conn->dst_port);
    hx_u32 seq = hx_htonl(conn->snd_nxt);
    hx_u32 ack = hx_htonl(conn->rcv_nxt);
    hx_u16 wnd = hx_htons(conn->rcv_wnd);
    memcpy(tcp + 0, &sp, 2);                             /* src_port */
    memcpy(tcp + 2, &dp, 2);                             /* dst_port */
    memcpy(tcp + 4, &seq, 4);                            /* seq */
    memcpy(tcp + 8, &ack, 4);                            /* ack */
    tcp[12] = (HX_TCP_HDR_LEN / 4) << 4;                /* data_off */
    tcp[13] = flags;                                      /* flags */
    memcpy(tcp + 14, &wnd, 2);                           /* window */
    /* checksum at tcp+16, urgent at tcp+18 — already zeroed */

    /* Payload directly after TCP header */
    if (payload && payload_len > 0)
        memcpy(tcp + HX_TCP_HDR_LEN, payload, payload_len);

    /* TCP checksum over pseudo-header + segment */
    hx_u16 tcp_cksum = hx_tcp_checksum(conn->src_ip, conn->dst_ip,
                                        tcp, tcp_seg_len);
    memcpy(tcp + 16, &tcp_cksum, 2);

    pkt->len = frame_len;

    hx_pkt_t *pkts[1] = { pkt };
    int sent = hx_pktio_tx_burst(conn->pktio, pkts, 1);
    if (sent != 1) {
        hx_pktio_free_pkt(conn->pktio, pkt);
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

    /* Convert from network byte order to host order */
    hdr->src_port = hx_ntohs(hdr->src_port);
    hdr->dst_port = hx_ntohs(hdr->dst_port);
    hdr->seq      = hx_ntohl(hdr->seq);
    hdr->ack      = hx_ntohl(hdr->ack);
    hdr->window   = hx_ntohs(hdr->window);

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

hx_result_t hx_tcp_retransmit_syn(hx_tcp_conn_t *conn)
{
    if (!conn)
        return HX_ERR_INVAL;
    if (conn->state != HX_TCP_SYN_SENT)
        return HX_ERR_INVAL;

    /*
     * Rewind snd_nxt to the original ISN (snd_una) so the SYN
     * carries the same sequence number. The peer's SYN-ACK will
     * ack ISN+1 which matches our snd_nxt after re-advance.
     */
    conn->snd_nxt = conn->snd_una;

    if (conn->pktio) {
        hx_result_t rc = hx_tcp_send_segment(conn, HX_TCP_FLAG_SYN, NULL, 0);
        if (rc != HX_OK) {
            conn->snd_nxt = conn->snd_una + 1; /* restore */
            return rc;
        }
    }

    conn->snd_nxt = conn->snd_una + 1; /* SYN consumes 1 seq */
    return HX_OK;
}

hx_result_t hx_tcp_send(hx_tcp_conn_t *conn,
                         const hx_u8 *data, hx_u32 len)
{
    if (!conn || !data)
        return HX_ERR_INVAL;
    if (conn->state != HX_TCP_ESTABLISHED)
        return HX_ERR_INVAL;

    /* Segment data into MSS-sized chunks (account for Eth+IP+TCP headers) */
    hx_u32 mss = HX_MAX_PKT_SIZE - HX_FRAME_HDR_LEN - HX_TCP_HDR_LEN;
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

hx_result_t hx_tcp_input_frame(hx_tcp_conn_t *conn, const hx_pkt_t *pkt)
{
    if (!conn || !pkt)
        return HX_ERR_INVAL;

    hx_u32 src_ip, dst_ip;
    const hx_u8 *tcp_seg;
    hx_u32 tcp_len;

    hx_result_t rc = hx_net_parse_frame(pkt->data, pkt->len,
                                         &src_ip, &dst_ip,
                                         &tcp_seg, &tcp_len);
    if (rc != HX_OK)
        return rc;

    /* Build a temporary pkt pointing at the TCP segment */
    hx_pkt_t tcp_pkt;
    tcp_pkt.data    = (hx_u8 *)tcp_seg;
    tcp_pkt.len     = tcp_len;
    tcp_pkt.buf_len = tcp_len;
    tcp_pkt.opaque  = NULL;

    return hx_tcp_input(conn, &tcp_pkt);
}
