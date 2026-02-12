#ifndef HURRICANE_NET_H
#define HURRICANE_NET_H

#include "common.h"

/*
 * Network frame construction and parsing layer.
 *
 * Provides Ethernet + IPv4 header handling so the TCP state machine
 * can produce complete L2 frames for transmission and parse
 * incoming frames from the wire.
 */

/* Ethernet header (14 bytes) */
typedef struct hx_ether_hdr {
    hx_u8  dst_mac[6];
    hx_u8  src_mac[6];
    hx_u16 ether_type;   /* network byte order: 0x0800 = IPv4 */
} hx_ether_hdr_t;

/* IPv4 header (20 bytes, no options) */
typedef struct hx_ipv4_hdr {
    hx_u8  ver_ihl;      /* version(4) + IHL(4) */
    hx_u8  tos;
    hx_u16 total_len;    /* network byte order */
    hx_u16 id;           /* network byte order */
    hx_u16 frag_off;     /* network byte order */
    hx_u8  ttl;
    hx_u8  protocol;     /* 6 = TCP */
    hx_u16 checksum;     /* network byte order */
    hx_u32 src_ip;       /* network byte order */
    hx_u32 dst_ip;       /* network byte order */
} hx_ipv4_hdr_t;

#define HX_ETHER_TYPE_IPV4  0x0800
#define HX_IP_PROTO_TCP     6
#define HX_IP_DEFAULT_TTL   64

/* Total L2+L3 header overhead */
#define HX_FRAME_HDR_LEN  (HX_ETHER_HDR_LEN + HX_IPV4_HDR_LEN)

/* --- Byte order conversion --------------------------------------------- */

hx_u16 hx_htons(hx_u16 x);
hx_u16 hx_ntohs(hx_u16 x);
hx_u32 hx_htonl(hx_u32 x);
hx_u32 hx_ntohl(hx_u32 x);

/* --- Checksums --------------------------------------------------------- */

/* IP header checksum (RFC 1071 one's complement sum) */
hx_u16 hx_ip_checksum(const void *data, hx_u32 len);

/* TCP checksum with 12-byte pseudo-header */
hx_u16 hx_tcp_checksum(hx_u32 src_ip, hx_u32 dst_ip,
                        const hx_u8 *tcp_seg, hx_u32 tcp_len);

/* --- Frame construction / parsing -------------------------------------- */

/*
 * Build a complete L2 frame: Ethernet + IPv4 + TCP segment.
 *
 * tcp_seg/tcp_len: already-built TCP segment (header + payload).
 * Writes into buf, returns total frame length. Returns 0 on error.
 */
hx_u32 hx_net_build_frame(const hx_u8 src_mac[6], const hx_u8 dst_mac[6],
                           hx_u32 src_ip, hx_u32 dst_ip,
                           const hx_u8 *tcp_seg, hx_u32 tcp_len,
                           hx_u8 *buf, hx_u32 buf_size);

/*
 * Parse a complete L2 frame, strip Ethernet + IPv4 headers.
 *
 * On success: outputs src_ip, dst_ip, pointer to TCP segment, tcp_len.
 * Returns HX_OK on success, HX_ERR_PROTO on malformed frame.
 */
hx_result_t hx_net_parse_frame(const hx_u8 *frame, hx_u32 frame_len,
                                hx_u32 *src_ip, hx_u32 *dst_ip,
                                const hx_u8 **tcp_seg, hx_u32 *tcp_len);

#endif /* HURRICANE_NET_H */
