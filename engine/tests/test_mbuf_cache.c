#include "hurricane/mbuf_cache.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* --- Template sizes ---------------------------------------------------- */

static void test_ack_template(void)
{
    struct hx_mbuf_cache cache;
    hx_u8 src_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    hx_u8 dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    hx_mbuf_cache_init_tcp(&cache, src_mac, dst_mac,
                            HX_TCP_FLAG_ACK, false, NULL, 0);

    assert(cache.tmpl.l2_len == 14);
    assert(cache.tmpl.l3_len == 20);
    assert(cache.tmpl.l4_len == 20);
    assert(cache.tmpl.payload_len == 0);
    assert(cache.tmpl.total_len == 54); /* 14 + 20 + 20 */

    /* Verify Ethernet header */
    assert(memcmp(cache.tmpl.data + 0, dst_mac, 6) == 0);
    assert(memcmp(cache.tmpl.data + 6, src_mac, 6) == 0);
    hx_u16 etype;
    memcpy(&etype, cache.tmpl.data + 12, 2);
    assert(etype == hx_htons(HX_ETHER_TYPE_IPV4));

    /* Verify IP header */
    hx_u8 *ip = cache.tmpl.data + 14;
    assert(ip[0] == 0x45);
    assert(ip[8] == HX_IP_DEFAULT_TTL);
    assert(ip[9] == HX_IP_PROTO_TCP);

    /* Verify TCP header */
    hx_u8 *tcp = cache.tmpl.data + 34;
    assert(tcp[12] == ((20 / 4) << 4)); /* data_off = 5 */
    assert(tcp[13] == HX_TCP_FLAG_ACK);
    hx_u16 wnd;
    memcpy(&wnd, tcp + 14, 2);
    assert(wnd == hx_htons(65535));

    printf("  PASS: test_ack_template\n");
}

static void test_syn_template(void)
{
    struct hx_mbuf_cache cache;
    hx_u8 src_mac[6] = {0};
    hx_u8 dst_mac[6] = {0};

    hx_mbuf_cache_init_tcp(&cache, src_mac, dst_mac,
                            HX_TCP_FLAG_SYN, true, NULL, 0);

    assert(cache.tmpl.l4_len == 24); /* 20 + 4 MSS option */
    assert(cache.tmpl.total_len == 58); /* 14 + 20 + 24 */

    /* Verify TCP data_off includes option */
    hx_u8 *tcp = cache.tmpl.data + 34;
    assert(tcp[12] == ((24 / 4) << 4)); /* data_off = 6 */
    assert(tcp[13] == HX_TCP_FLAG_SYN);

    /* Verify MSS option: Kind=2, Len=4, MSS=1460 (0x05B4) */
    hx_u8 *opt = tcp + 20;
    assert(opt[0] == 0x02);
    assert(opt[1] == 0x04);
    assert(opt[2] == 0x05);
    assert(opt[3] == 0xB4);

    printf("  PASS: test_syn_template\n");
}

static void test_data_template(void)
{
    struct hx_mbuf_cache cache;
    hx_u8 src_mac[6] = {0};
    hx_u8 dst_mac[6] = {0};

    const char *http_req = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
    hx_u32 req_len = (hx_u32)strlen(http_req);

    hx_mbuf_cache_init_tcp(&cache, src_mac, dst_mac,
                            HX_TCP_FLAG_ACK | HX_TCP_FLAG_PSH,
                            false,
                            (const hx_u8 *)http_req, req_len);

    assert(cache.tmpl.l4_len == 20);
    assert(cache.tmpl.payload_len == req_len);
    assert(cache.tmpl.total_len == 54 + req_len);

    /* Verify payload in template */
    hx_u8 *payload = cache.tmpl.data + 54;
    assert(memcmp(payload, http_req, req_len) == 0);

    printf("  PASS: test_data_template\n");
}

/* --- Template fill ----------------------------------------------------- */

static void test_tmpl_fill(void)
{
    struct hx_mbuf_cache cache;
    hx_u8 src_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    hx_u8 dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    hx_mbuf_cache_init_tcp(&cache, src_mac, dst_mac,
                            HX_TCP_FLAG_ACK, false, NULL, 0);

    /* Copy template to a working buffer (simulates mbuf alloc) */
    hx_u8 pkt[HX_MBUF_DATA_SIZE];
    memcpy(pkt, cache.tmpl.data, cache.tmpl.total_len);

    /* Fill dynamic fields */
    hx_u32 laddr = hx_htonl(0xC0A80001);
    hx_u32 faddr = hx_htonl(0x0A000001);
    hx_u16 lport = hx_htons(12345);
    hx_u16 fport = hx_htons(80);
    hx_u32 seq   = hx_htonl(1000);
    hx_u32 ack   = hx_htonl(2000);
    hx_u16 ip_id = hx_htons(42);
    hx_u16 csum_ip  = 0x1234;
    hx_u16 csum_tcp = 0x5678;

    hx_tmpl_fill(&cache, pkt,
                  laddr, faddr, lport, fport,
                  seq, ack, HX_TCP_FLAG_ACK,
                  ip_id, csum_ip, csum_tcp);

    /* Verify IP fields */
    hx_u8 *ip = pkt + 14;
    hx_u16 got_id;
    memcpy(&got_id, ip + 4, 2);
    assert(got_id == ip_id);

    hx_u32 got_src_ip;
    memcpy(&got_src_ip, ip + 12, 4);
    assert(got_src_ip == laddr);

    hx_u32 got_dst_ip;
    memcpy(&got_dst_ip, ip + 16, 4);
    assert(got_dst_ip == faddr);

    /* Verify TCP fields */
    hx_u8 *tcp = pkt + 34;
    hx_u16 got_sport;
    memcpy(&got_sport, tcp + 0, 2);
    assert(got_sport == lport);

    hx_u16 got_dport;
    memcpy(&got_dport, tcp + 2, 2);
    assert(got_dport == fport);

    hx_u32 got_seq;
    memcpy(&got_seq, tcp + 4, 4);
    assert(got_seq == seq);

    hx_u32 got_ack;
    memcpy(&got_ack, tcp + 8, 4);
    assert(got_ack == ack);

    assert(tcp[13] == HX_TCP_FLAG_ACK);

    hx_u16 got_csum;
    memcpy(&got_csum, tcp + 16, 2);
    assert(got_csum == csum_tcp);

    /* Verify Ethernet header unchanged */
    assert(memcmp(pkt + 0, dst_mac, 6) == 0);
    assert(memcmp(pkt + 6, src_mac, 6) == 0);

    printf("  PASS: test_tmpl_fill\n");
}

/* --- Parse round-trip: build template, fill, parse back ---------------- */

static void test_template_roundtrip(void)
{
    struct hx_mbuf_cache cache;
    hx_u8 src_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    hx_u8 dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    hx_mbuf_cache_init_tcp(&cache, src_mac, dst_mac,
                            HX_TCP_FLAG_SYN, true, NULL, 0);

    hx_u8 pkt[HX_MBUF_DATA_SIZE];
    memcpy(pkt, cache.tmpl.data, cache.tmpl.total_len);

    hx_u32 laddr = hx_htonl(0xC0A80001);
    hx_u32 faddr = hx_htonl(0x0A000002);

    hx_tmpl_fill(&cache, pkt,
                  laddr, faddr,
                  hx_htons(54321), hx_htons(443),
                  hx_htonl(99999), hx_htonl(0),
                  HX_TCP_FLAG_SYN,
                  hx_htons(1), 0, 0);

    /* Fill IP checksum properly for parse validation */
    hx_u8 *ip = pkt + 14;
    memset(ip + 10, 0, 2); /* clear checksum */
    hx_u16 cksum = hx_ip_checksum(ip, HX_IPV4_HDR_LEN);
    memcpy(ip + 10, &cksum, 2);

    /* Parse the frame back */
    hx_u32 parsed_src, parsed_dst;
    const hx_u8 *tcp_seg;
    hx_u32 tcp_len;

    hx_result_t rc = hx_net_parse_frame(pkt, cache.tmpl.total_len,
                                         &parsed_src, &parsed_dst,
                                         &tcp_seg, &tcp_len);
    assert(rc == HX_OK);
    assert(parsed_src == 0xC0A80001);
    assert(parsed_dst == 0x0A000002);
    assert(tcp_len == 24); /* 20 + 4 MSS option */

    /* Verify TCP fields in parsed segment */
    hx_u16 sport;
    memcpy(&sport, tcp_seg + 0, 2);
    assert(sport == hx_htons(54321));

    hx_u16 dport;
    memcpy(&dport, tcp_seg + 2, 2);
    assert(dport == hx_htons(443));

    printf("  PASS: test_template_roundtrip\n");
}

int main(void)
{
    printf("test_mbuf_cache:\n");
    test_ack_template();
    test_syn_template();
    test_data_template();
    test_tmpl_fill();
    test_template_roundtrip();
    printf("All mbuf_cache tests passed.\n");
    return 0;
}
