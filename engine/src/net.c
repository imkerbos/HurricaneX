#include "hurricane/net.h"
#include <string.h>

/*
 * Network frame construction and parsing.
 *
 * Builds complete Ethernet + IPv4 + TCP frames for wire transmission
 * and parses incoming frames back into their components.
 */

/* --- Byte order helpers ------------------------------------------------ */

/*
 * Compile-time endianness detection.
 * Most modern compilers define __BYTE_ORDER__ or we can check common macros.
 */
static inline int hx_is_little_endian(void)
{
    const hx_u16 one = 1;
    return *(const hx_u8 *)&one;
}

hx_u16 hx_htons(hx_u16 x)
{
    if (hx_is_little_endian())
        return (hx_u16)((x >> 8) | (x << 8));
    return x;
}

hx_u16 hx_ntohs(hx_u16 x)
{
    return hx_htons(x); /* symmetric */
}

hx_u32 hx_htonl(hx_u32 x)
{
    if (hx_is_little_endian())
        return ((x >> 24) & 0x000000FF) |
               ((x >>  8) & 0x0000FF00) |
               ((x <<  8) & 0x00FF0000) |
               ((x << 24) & 0xFF000000);
    return x;
}

hx_u32 hx_ntohl(hx_u32 x)
{
    return hx_htonl(x); /* symmetric */
}

/* --- Checksums --------------------------------------------------------- */

hx_u16 hx_ip_checksum(const void *data, hx_u32 len)
{
    const hx_u8 *p = (const hx_u8 *)data;
    hx_u32 sum = 0;

    /* Sum 16-bit words */
    while (len > 1) {
        hx_u16 word;
        memcpy(&word, p, 2);
        sum += word;
        p += 2;
        len -= 2;
    }

    /* Odd trailing byte */
    if (len == 1)
        sum += *p;

    /* Fold 32-bit sum into 16 bits */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (hx_u16)(~sum);
}

hx_u16 hx_tcp_checksum(hx_u32 src_ip, hx_u32 dst_ip,
                        const hx_u8 *tcp_seg, hx_u32 tcp_len)
{
    hx_u32 sum = 0;

    /* 12-byte pseudo-header (all fields in network byte order) */
    hx_u32 src_n = hx_htonl(src_ip);
    hx_u32 dst_n = hx_htonl(dst_ip);
    hx_u16 proto = hx_htons(HX_IP_PROTO_TCP);
    hx_u16 tlen  = hx_htons((hx_u16)tcp_len);

    /* Accumulate pseudo-header as 16-bit words */
    sum += (src_n >> 16) & 0xFFFF;
    sum += src_n & 0xFFFF;
    sum += (dst_n >> 16) & 0xFFFF;
    sum += dst_n & 0xFFFF;
    sum += proto;
    sum += tlen;

    /* Accumulate TCP segment */
    const hx_u8 *p = tcp_seg;
    hx_u32 remaining = tcp_len;
    while (remaining > 1) {
        hx_u16 word;
        memcpy(&word, p, 2);
        sum += word;
        p += 2;
        remaining -= 2;
    }
    if (remaining == 1)
        sum += *p;

    /* Fold and complement */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (hx_u16)(~sum);
}

/* --- Frame construction ------------------------------------------------ */

hx_u32 hx_net_build_frame(const hx_u8 src_mac[6], const hx_u8 dst_mac[6],
                           hx_u32 src_ip, hx_u32 dst_ip,
                           const hx_u8 *tcp_seg, hx_u32 tcp_len,
                           hx_u8 *buf, hx_u32 buf_size)
{
    hx_u32 total = HX_FRAME_HDR_LEN + tcp_len;
    if (!buf || !tcp_seg || total > buf_size)
        return 0;

    /* Ethernet header */
    hx_ether_hdr_t eth;
    memcpy(eth.dst_mac, dst_mac, 6);
    memcpy(eth.src_mac, src_mac, 6);
    eth.ether_type = hx_htons(HX_ETHER_TYPE_IPV4);
    memcpy(buf, &eth, HX_ETHER_HDR_LEN);

    /* IPv4 header */
    hx_ipv4_hdr_t ip;
    memset(&ip, 0, sizeof(ip));
    ip.ver_ihl   = 0x45;  /* version 4, IHL 5 (20 bytes) */
    ip.tos       = 0;
    ip.total_len = hx_htons((hx_u16)(HX_IPV4_HDR_LEN + tcp_len));
    ip.id        = 0;
    ip.frag_off  = 0;
    ip.ttl       = HX_IP_DEFAULT_TTL;
    ip.protocol  = HX_IP_PROTO_TCP;
    ip.checksum  = 0;
    ip.src_ip    = hx_htonl(src_ip);
    ip.dst_ip    = hx_htonl(dst_ip);
    ip.checksum  = hx_ip_checksum(&ip, HX_IPV4_HDR_LEN);
    memcpy(buf + HX_ETHER_HDR_LEN, &ip, HX_IPV4_HDR_LEN);

    /* TCP segment (already built by caller) */
    memcpy(buf + HX_FRAME_HDR_LEN, tcp_seg, tcp_len);

    return total;
}

/* --- Frame parsing ----------------------------------------------------- */

hx_result_t hx_net_parse_frame(const hx_u8 *frame, hx_u32 frame_len,
                                hx_u32 *src_ip, hx_u32 *dst_ip,
                                const hx_u8 **tcp_seg, hx_u32 *tcp_len)
{
    if (!frame || !src_ip || !dst_ip || !tcp_seg || !tcp_len)
        return HX_ERR_INVAL;

    /* Need at least Ethernet + IPv4 headers */
    if (frame_len < HX_FRAME_HDR_LEN)
        return HX_ERR_PROTO;

    /* Check EtherType = IPv4 */
    hx_ether_hdr_t eth;
    memcpy(&eth, frame, HX_ETHER_HDR_LEN);
    if (hx_ntohs(eth.ether_type) != HX_ETHER_TYPE_IPV4)
        return HX_ERR_PROTO;

    /* Parse IPv4 header */
    hx_ipv4_hdr_t ip;
    memcpy(&ip, frame + HX_ETHER_HDR_LEN, HX_IPV4_HDR_LEN);

    /* Validate version and IHL */
    hx_u8 version = (ip.ver_ihl >> 4) & 0x0F;
    hx_u8 ihl = ip.ver_ihl & 0x0F;
    if (version != 4 || ihl < 5)
        return HX_ERR_PROTO;

    hx_u32 ip_hdr_len = (hx_u32)ihl * 4;
    if (HX_ETHER_HDR_LEN + ip_hdr_len > frame_len)
        return HX_ERR_PROTO;

    /* Check protocol = TCP */
    if (ip.protocol != HX_IP_PROTO_TCP)
        return HX_ERR_PROTO;

    hx_u16 ip_total = hx_ntohs(ip.total_len);
    if (ip_total < ip_hdr_len || HX_ETHER_HDR_LEN + ip_total > frame_len)
        return HX_ERR_PROTO;

    *src_ip  = hx_ntohl(ip.src_ip);
    *dst_ip  = hx_ntohl(ip.dst_ip);
    *tcp_seg = frame + HX_ETHER_HDR_LEN + ip_hdr_len;
    *tcp_len = ip_total - ip_hdr_len;

    return HX_OK;
}
