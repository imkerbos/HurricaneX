#include "hurricane/net.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* --- Byte order tests -------------------------------------------------- */

static void test_byte_order(void)
{
    /* Known values */
    assert(hx_htons(0x0102) == 0x0201 || hx_htons(0x0102) == 0x0102);
    /* Round-trip */
    assert(hx_ntohs(hx_htons(0x1234)) == 0x1234);
    assert(hx_ntohl(hx_htonl(0xDEADBEEF)) == 0xDEADBEEF);
    assert(hx_ntohs(hx_htons(0)) == 0);
    assert(hx_ntohl(hx_htonl(0)) == 0);
    assert(hx_ntohs(hx_htons(0xFFFF)) == 0xFFFF);
    assert(hx_ntohl(hx_htonl(0xFFFFFFFF)) == 0xFFFFFFFF);
    printf("  PASS: test_byte_order\n");
}

/* --- IP checksum tests ------------------------------------------------- */

static void test_ip_checksum(void)
{
    /*
     * RFC 1071 example: 20-byte IPv4 header with known checksum.
     * We build a header, compute checksum, then verify re-computing
     * over the entire header (with checksum field) yields 0.
     */
    hx_ipv4_hdr_t ip;
    memset(&ip, 0, sizeof(ip));
    ip.ver_ihl   = 0x45;
    ip.tos       = 0;
    ip.total_len = hx_htons(40);  /* 20 IP + 20 TCP */
    ip.id        = hx_htons(1);
    ip.frag_off  = 0;
    ip.ttl       = 64;
    ip.protocol  = HX_IP_PROTO_TCP;
    ip.checksum  = 0;
    ip.src_ip    = hx_htonl(0xC0A80001); /* 192.168.0.1 */
    ip.dst_ip    = hx_htonl(0xC0A80002); /* 192.168.0.2 */

    ip.checksum = hx_ip_checksum(&ip, HX_IPV4_HDR_LEN);
    assert(ip.checksum != 0);

    /* Verify: checksum over entire header with checksum field should be 0 */
    hx_u16 verify = hx_ip_checksum(&ip, HX_IPV4_HDR_LEN);
    assert(verify == 0);

    printf("  PASS: test_ip_checksum\n");
}

/* --- TCP checksum tests ------------------------------------------------ */

static void test_tcp_checksum(void)
{
    /* Build a minimal TCP header (20 bytes, no payload) */
    hx_u8 tcp_seg[20];
    memset(tcp_seg, 0, sizeof(tcp_seg));

    /* src_port=1234, dst_port=80 in network byte order */
    hx_u16 sp = hx_htons(1234);
    hx_u16 dp = hx_htons(80);
    memcpy(tcp_seg + 0, &sp, 2);
    memcpy(tcp_seg + 2, &dp, 2);
    /* data_off = 5 words */
    tcp_seg[12] = (5 << 4);
    /* flags = SYN */
    tcp_seg[13] = HX_TCP_FLAG_SYN;

    hx_u32 src_ip = 0xC0A80001;
    hx_u32 dst_ip = 0xC0A80002;

    hx_u16 cksum = hx_tcp_checksum(src_ip, dst_ip, tcp_seg, 20);
    assert(cksum != 0);

    /* Write checksum into TCP header and re-verify */
    memcpy(tcp_seg + 16, &cksum, 2);
    hx_u16 verify = hx_tcp_checksum(src_ip, dst_ip, tcp_seg, 20);
    assert(verify == 0);

    printf("  PASS: test_tcp_checksum\n");
}

/* --- Build + parse round-trip ------------------------------------------ */

static void test_build_parse_roundtrip(void)
{
    hx_u8 src_mac[6] = {0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03};
    hx_u8 dst_mac[6] = {0xDD, 0xEE, 0xFF, 0x04, 0x05, 0x06};
    hx_u32 src_ip = 0x0A000001; /* 10.0.0.1 */
    hx_u32 dst_ip = 0x0A000002; /* 10.0.0.2 */

    /* Fake TCP segment: 20-byte header + 5-byte payload */
    hx_u8 tcp_seg[25];
    memset(tcp_seg, 0, 20);
    tcp_seg[12] = (5 << 4); /* data_off = 5 words */
    tcp_seg[13] = HX_TCP_FLAG_ACK;
    memcpy(tcp_seg + 20, "hello", 5);

    hx_u8 frame[HX_MAX_PKT_SIZE];
    hx_u32 frame_len = hx_net_build_frame(src_mac, dst_mac,
                                           src_ip, dst_ip,
                                           tcp_seg, 25,
                                           frame, sizeof(frame));
    assert(frame_len == HX_FRAME_HDR_LEN + 25);

    /* Verify IP checksum in the built frame */
    hx_ipv4_hdr_t ip_hdr;
    memcpy(&ip_hdr, frame + HX_ETHER_HDR_LEN, HX_IPV4_HDR_LEN);
    assert(hx_ip_checksum(&ip_hdr, HX_IPV4_HDR_LEN) == 0);

    /* Parse it back */
    hx_u32 parsed_src, parsed_dst;
    const hx_u8 *parsed_tcp;
    hx_u32 parsed_tcp_len;

    hx_result_t rc = hx_net_parse_frame(frame, frame_len,
                                         &parsed_src, &parsed_dst,
                                         &parsed_tcp, &parsed_tcp_len);
    assert(rc == HX_OK);
    assert(parsed_src == src_ip);
    assert(parsed_dst == dst_ip);
    assert(parsed_tcp_len == 25);
    assert(memcmp(parsed_tcp, tcp_seg, 25) == 0);

    /* Verify MAC addresses in frame */
    assert(memcmp(frame, dst_mac, 6) == 0);
    assert(memcmp(frame + 6, src_mac, 6) == 0);

    printf("  PASS: test_build_parse_roundtrip\n");
}

/* --- Malformed frame rejection ----------------------------------------- */

static void test_short_frame(void)
{
    hx_u8 frame[10] = {0};
    hx_u32 src, dst;
    const hx_u8 *tcp;
    hx_u32 tlen;

    assert(hx_net_parse_frame(frame, 10, &src, &dst, &tcp, &tlen)
           == HX_ERR_PROTO);
    printf("  PASS: test_short_frame\n");
}

static void test_wrong_ether_type(void)
{
    hx_u8 frame[HX_FRAME_HDR_LEN + 20];
    memset(frame, 0, sizeof(frame));

    /* Set ether_type to ARP (0x0806) instead of IPv4 */
    hx_u16 arp_type = hx_htons(0x0806);
    memcpy(frame + 12, &arp_type, 2);

    /* Fill minimal IPv4 header so it's not rejected for other reasons */
    frame[HX_ETHER_HDR_LEN] = 0x45;

    hx_u32 src, dst;
    const hx_u8 *tcp;
    hx_u32 tlen;

    assert(hx_net_parse_frame(frame, sizeof(frame), &src, &dst, &tcp, &tlen)
           == HX_ERR_PROTO);
    printf("  PASS: test_wrong_ether_type\n");
}

static void test_wrong_protocol(void)
{
    hx_u8 frame[HX_FRAME_HDR_LEN + 20];
    memset(frame, 0, sizeof(frame));

    /* Valid Ethernet header with IPv4 type */
    hx_u16 ipv4_type = hx_htons(HX_ETHER_TYPE_IPV4);
    memcpy(frame + 12, &ipv4_type, 2);

    /* IPv4 header with protocol = UDP (17) instead of TCP */
    frame[HX_ETHER_HDR_LEN] = 0x45;
    hx_u16 total_len = hx_htons(HX_IPV4_HDR_LEN + 20);
    memcpy(frame + HX_ETHER_HDR_LEN + 2, &total_len, 2);
    frame[HX_ETHER_HDR_LEN + 8] = 64;  /* TTL */
    frame[HX_ETHER_HDR_LEN + 9] = 17;  /* UDP */

    hx_u32 src, dst;
    const hx_u8 *tcp;
    hx_u32 tlen;

    assert(hx_net_parse_frame(frame, sizeof(frame), &src, &dst, &tcp, &tlen)
           == HX_ERR_PROTO);
    printf("  PASS: test_wrong_protocol\n");
}

static void test_null_params(void)
{
    assert(hx_net_parse_frame(NULL, 0, NULL, NULL, NULL, NULL)
           == HX_ERR_INVAL);

    hx_u8 frame[HX_FRAME_HDR_LEN];
    assert(hx_net_build_frame(NULL, NULL, 0, 0, NULL, 0,
                               frame, sizeof(frame)) == 0);
    printf("  PASS: test_null_params\n");
}

static void test_buffer_too_small(void)
{
    hx_u8 src_mac[6] = {0};
    hx_u8 dst_mac[6] = {0};
    hx_u8 tcp_seg[20] = {0};
    hx_u8 buf[10]; /* way too small */

    assert(hx_net_build_frame(src_mac, dst_mac, 0, 0,
                               tcp_seg, 20, buf, sizeof(buf)) == 0);
    printf("  PASS: test_buffer_too_small\n");
}

int main(void)
{
    printf("test_net:\n");
    test_byte_order();
    test_ip_checksum();
    test_tcp_checksum();
    test_build_parse_roundtrip();
    test_short_frame();
    test_wrong_ether_type();
    test_wrong_protocol();
    test_null_params();
    test_buffer_too_small();
    printf("All net tests passed.\n");
    return 0;
}
