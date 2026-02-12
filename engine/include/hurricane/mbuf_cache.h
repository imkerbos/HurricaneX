#ifndef HURRICANE_MBUF_CACHE_H
#define HURRICANE_MBUF_CACHE_H

#include "common.h"
#include "net.h"
#include <string.h>

/*
 * Packet template cache — inspired by dperf mbuf_cache.
 *
 * Pre-builds complete Eth+IP+TCP[+options][+payload] packets at init time.
 * At send time, only 6 dynamic fields are modified (src/dst IP/port, seq, ack).
 *
 * Three templates per worker:
 *   tcp_opt  — SYN packet (TCP header + MSS option, 24 bytes TCP)
 *   tcp_data — PSH+ACK packet (TCP header + HTTP payload)
 *   tcp      — ACK/FIN packet (bare 20-byte TCP header)
 *
 * In AF_XDP mode, packets live in UMEM frames for zero-copy TX.
 * In mock mode, uses hx_mempool.
 */

#define HX_MBUF_DATA_SIZE 2048

/* Template packet data */
struct hx_mbuf_data {
    hx_u8   data[HX_MBUF_DATA_SIZE]; /* complete packet bytes */
    hx_u16  l2_len;                   /* Ethernet header length */
    hx_u16  l3_len;                   /* IPv4 header length */
    hx_u16  l4_len;                   /* TCP header length (incl options) */
    hx_u16  payload_len;              /* HTTP payload length */
    hx_u16  total_len;                /* total packet length */
    hx_u16  pad;
};

/* Template cache */
struct hx_mbuf_cache {
    struct hx_mbuf_data tmpl;         /* template packet */
};

/*
 * Build a TCP template packet.
 *
 * Constructs Eth + IPv4 + TCP header into tmpl.data.
 * IP/TCP fields that vary per-connection (addrs, ports, seq, ack)
 * are zeroed — they'll be filled at send time.
 *
 * Parameters:
 *   cache     — output cache to initialize
 *   src_mac   — source MAC (our NIC)
 *   dst_mac   — destination MAC (gateway)
 *   tcp_flags — default TCP flags for this template
 *   tcp_opt   — if true, append MSS option (4 bytes)
 *   payload   — HTTP payload to append (NULL for no payload)
 *   payload_len — length of payload
 */
void hx_mbuf_cache_init_tcp(struct hx_mbuf_cache *cache,
                             const hx_u8 src_mac[6],
                             const hx_u8 dst_mac[6],
                             hx_u8 tcp_flags,
                             bool tcp_opt,
                             const hx_u8 *payload,
                             hx_u32 payload_len);

/*
 * Allocate a packet from the template.
 *
 * In mock mode: allocates from mempool, copies template data.
 * Returns pointer to packet data buffer and sets *out_len to total_len.
 *
 * Caller must fill dynamic fields (IP addrs, TCP ports, seq, ack, checksum)
 * before sending.
 */

/* Offsets into template for fast field access */
static inline hx_u8 *hx_tmpl_ip(struct hx_mbuf_cache *c, hx_u8 *pkt)
{
    return pkt + c->tmpl.l2_len;
}

static inline hx_u8 *hx_tmpl_tcp(struct hx_mbuf_cache *c, hx_u8 *pkt)
{
    return pkt + c->tmpl.l2_len + c->tmpl.l3_len;
}

/*
 * Fill dynamic fields in a packet allocated from template.
 * This is the hot path — only 6 field writes + checksum write.
 */
static inline void hx_tmpl_fill(struct hx_mbuf_cache *c, hx_u8 *pkt,
                                 hx_u32 laddr_n, hx_u32 faddr_n,
                                 hx_u16 lport_n, hx_u16 fport_n,
                                 hx_u32 seq_n, hx_u32 ack_n,
                                 hx_u8 tcp_flags,
                                 hx_u16 ip_id_n,
                                 hx_u16 csum_ip,
                                 hx_u16 csum_tcp)
{
    hx_u8 *ip  = pkt + c->tmpl.l2_len;
    hx_u8 *tcp = ip + c->tmpl.l3_len;

    /* IP header dynamic fields */
    memcpy(ip + 4, &ip_id_n, 2);       /* IP ID */
    memcpy(ip + 10, &csum_ip, 2);      /* IP checksum */
    memcpy(ip + 12, &laddr_n, 4);      /* src IP */
    memcpy(ip + 16, &faddr_n, 4);      /* dst IP */

    /* TCP header dynamic fields */
    memcpy(tcp + 0, &lport_n, 2);      /* src port */
    memcpy(tcp + 2, &fport_n, 2);      /* dst port */
    memcpy(tcp + 4, &seq_n, 4);        /* seq */
    memcpy(tcp + 8, &ack_n, 4);        /* ack */
    tcp[13] = tcp_flags;                /* flags */
    memcpy(tcp + 16, &csum_tcp, 2);    /* TCP checksum */
}

#endif /* HURRICANE_MBUF_CACHE_H */
