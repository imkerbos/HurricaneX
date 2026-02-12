#include "hurricane/mbuf_cache.h"
#include <string.h>

/*
 * Packet template construction.
 *
 * Builds a complete Eth + IPv4 + TCP [+ options] [+ payload] template.
 * Dynamic fields (IPs, ports, seq, ack, checksums) are zeroed —
 * they'll be filled per-packet at send time via hx_tmpl_fill().
 */

/* TCP MSS option: Kind=2, Len=4, MSS=1460 */
static const hx_u8 tcp_mss_option[4] = { 0x02, 0x04, 0x05, 0xB4 };

void hx_mbuf_cache_init_tcp(struct hx_mbuf_cache *cache,
                             const hx_u8 src_mac[6],
                             const hx_u8 dst_mac[6],
                             hx_u8 tcp_flags,
                             bool tcp_opt,
                             const hx_u8 *payload,
                             hx_u32 payload_len)
{
    struct hx_mbuf_data *t = &cache->tmpl;
    memset(t, 0, sizeof(*t));

    hx_u16 tcp_hdr_len = HX_TCP_HDR_LEN + (tcp_opt ? 4 : 0); /* 20 or 24 */
    hx_u16 offset = 0;

    /* --- Ethernet header (14 bytes) --- */
    t->l2_len = HX_ETHER_HDR_LEN;
    memcpy(t->data + 0, dst_mac, 6);
    memcpy(t->data + 6, src_mac, 6);
    hx_u16 etype = hx_htons(HX_ETHER_TYPE_IPV4);
    memcpy(t->data + 12, &etype, 2);
    offset = HX_ETHER_HDR_LEN;

    /* --- IPv4 header (20 bytes) --- */
    t->l3_len = HX_IPV4_HDR_LEN;
    hx_u8 *ip = t->data + offset;
    ip[0] = 0x45;                                           /* ver=4, ihl=5 */
    hx_u16 ip_total = hx_htons((hx_u16)(HX_IPV4_HDR_LEN + tcp_hdr_len + payload_len));
    memcpy(ip + 2, &ip_total, 2);                           /* total_len */
    /* ip[4..5] = ID — filled per-packet */
    ip[8] = HX_IP_DEFAULT_TTL;                               /* TTL */
    ip[9] = HX_IP_PROTO_TCP;                                 /* protocol */
    /* ip[10..11] = checksum — filled per-packet */
    /* ip[12..15] = src_ip — filled per-packet */
    /* ip[16..19] = dst_ip — filled per-packet */
    offset += HX_IPV4_HDR_LEN;

    /* --- TCP header (20 or 24 bytes) --- */
    t->l4_len = tcp_hdr_len;
    hx_u8 *tcp = t->data + offset;
    /* tcp[0..1] = src_port — filled per-packet */
    /* tcp[2..3] = dst_port — filled per-packet */
    /* tcp[4..7] = seq — filled per-packet */
    /* tcp[8..11] = ack — filled per-packet */
    tcp[12] = (hx_u8)((tcp_hdr_len / 4) << 4);              /* data_off */
    tcp[13] = tcp_flags;                                      /* flags (default) */
    hx_u16 wnd = hx_htons(65535);
    memcpy(tcp + 14, &wnd, 2);                               /* window */
    /* tcp[16..17] = checksum — filled per-packet */
    /* tcp[18..19] = urgent — zero */
    offset += HX_TCP_HDR_LEN;

    /* TCP MSS option (if SYN template) */
    if (tcp_opt) {
        memcpy(t->data + offset, tcp_mss_option, 4);
        offset += 4;
    }

    /* --- Payload (HTTP request/response) --- */
    t->payload_len = (hx_u16)payload_len;
    if (payload && payload_len > 0) {
        if (offset + payload_len <= HX_MBUF_DATA_SIZE) {
            memcpy(t->data + offset, payload, payload_len);
            offset += (hx_u16)payload_len;
        }
    }

    t->total_len = offset;
}
