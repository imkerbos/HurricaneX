/*
 * DPDK TX smoke test — send a single SYN frame out the wire.
 *
 * Verifies: EAL init → port open → alloc_pkt → build frame → tx_burst → close.
 * Use tcpdump on the peer/mirror to confirm the frame arrives.
 *
 * Requires: root, hugepages, NIC bound to vfio-pci.
 *
 * Usage:
 *   ./smoke_tx --lcores 0 -a <PCI_ADDR> -- <dst_mac> <src_ip> <dst_ip>
 *   e.g. ./smoke_tx --lcores 0 -a 7f:00.0 -- 02:ab:cd:ef:00:01 10.0.0.1 10.0.0.2
 *
 * If no extra args after --, sends with zeroed dst_mac and 10.0.0.1 → 10.0.0.2.
 */
#ifdef HX_USE_DPDK

#include "hurricane/dpdk.h"
#include "hurricane/pktio.h"
#include "hurricane/mempool.h"
#include "hurricane/net.h"
#include "hurricane/tcp.h"
#include "hurricane/log.h"

#include <rte_ethdev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Parse MAC address string "AA:BB:CC:DD:EE:FF" into 6-byte array */
static int parse_mac(const char *str, hx_u8 mac[6])
{
    unsigned int m[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (hx_u8)m[i];
    return 0;
}

/* Parse dotted-decimal IPv4 "A.B.C.D" into host-order u32 */
static int parse_ipv4(const char *str, hx_u32 *ip)
{
    unsigned int a, b, c, d;
    if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return -1;
    *ip = (a << 24) | (b << 16) | (c << 8) | d;
    return 0;
}

int main(int argc, char **argv)
{
    printf("=== HurricaneX DPDK TX smoke test ===\n");

    /* 1. EAL init (consumes EAL args, leaves app args after --) */
    hx_dpdk_config_t cfg = { .argc = argc, .argv = argv };
    hx_result_t rc = hx_dpdk_init(&cfg);
    if (rc != HX_OK) {
        fprintf(stderr, "FAIL: hx_dpdk_init: %s\n", hx_strerror(rc));
        return 1;
    }
    printf("PASS: EAL initialized\n");

    /* 2. Find app args after "--" */
    hx_u8 dst_mac[6] = {0};
    hx_u32 src_ip = 0x0A000001; /* 10.0.0.1 */
    hx_u32 dst_ip = 0x0A000002; /* 10.0.0.2 */

    int app_start = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            app_start = i + 1;
            break;
        }
    }

    if (app_start > 0 && app_start < argc) {
        if (parse_mac(argv[app_start], dst_mac) != 0) {
            fprintf(stderr, "FAIL: invalid dst_mac '%s'\n", argv[app_start]);
            return 1;
        }
        if (app_start + 1 < argc) {
            if (parse_ipv4(argv[app_start + 1], &src_ip) != 0) {
                fprintf(stderr, "FAIL: invalid src_ip '%s'\n", argv[app_start + 1]);
                return 1;
            }
        }
        if (app_start + 2 < argc) {
            if (parse_ipv4(argv[app_start + 2], &dst_ip) != 0) {
                fprintf(stderr, "FAIL: invalid dst_ip '%s'\n", argv[app_start + 2]);
                return 1;
            }
        }
    }

    printf("  dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           dst_mac[0], dst_mac[1], dst_mac[2],
           dst_mac[3], dst_mac[4], dst_mac[5]);
    printf("  src_ip:  %u.%u.%u.%u\n",
           (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
           (src_ip >> 8) & 0xFF, src_ip & 0xFF);
    printf("  dst_ip:  %u.%u.%u.%u\n",
           (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
           (dst_ip >> 8) & 0xFF, dst_ip & 0xFF);

    /* 3. Mempool + open DPDK port 0 */
    hx_mempool_t *mp = hx_mempool_create("smoke_tx", 64, 2048);
    if (!mp) {
        fprintf(stderr, "FAIL: hx_mempool_create\n");
        return 1;
    }

    hx_pktio_t io;
    rc = hx_pktio_init(&io, &hx_pktio_dpdk_ops, "dpdk:0", mp);
    if (rc != HX_OK) {
        fprintf(stderr, "FAIL: hx_pktio_init(dpdk:0): %s\n", hx_strerror(rc));
        hx_mempool_destroy(mp);
        return 1;
    }
    printf("PASS: port 0 opened\n");

    /* 4. Get port's own MAC address */
    hx_u8 src_mac[6];
    struct rte_ether_addr port_mac;
    if (rte_eth_macaddr_get(0, &port_mac) == 0) {
        memcpy(src_mac, port_mac.addr_bytes, 6);
    } else {
        memset(src_mac, 0, 6);
    }
    printf("  src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           src_mac[0], src_mac[1], src_mac[2],
           src_mac[3], src_mac[4], src_mac[5]);

    /* 5. Build a SYN packet manually */
    hx_pkt_t pkt_desc;
    rc = hx_pktio_alloc_pkt(&io, &pkt_desc, HX_MAX_PKT_SIZE);
    if (rc != HX_OK) {
        fprintf(stderr, "FAIL: hx_pktio_alloc_pkt: %s\n", hx_strerror(rc));
        hx_pktio_close(&io);
        hx_mempool_destroy(mp);
        return 1;
    }

    /* Build TCP SYN segment (20 bytes) */
    hx_u8 tcp_seg[HX_TCP_HDR_LEN];
    memset(tcp_seg, 0, sizeof(tcp_seg));
    hx_u16 sport_n = hx_htons(12345);
    hx_u16 dport_n = hx_htons(80);
    hx_u32 seq_n   = hx_htonl(1000);
    hx_u16 win_n   = hx_htons(65535);
    memcpy(tcp_seg + 0, &sport_n, 2);  /* src_port */
    memcpy(tcp_seg + 2, &dport_n, 2);  /* dst_port */
    memcpy(tcp_seg + 4, &seq_n, 4);    /* seq */
    tcp_seg[12] = (5 << 4);            /* data_off = 5 words */
    tcp_seg[13] = HX_TCP_FLAG_SYN;     /* flags */
    memcpy(tcp_seg + 14, &win_n, 2);   /* window */

    /* Compute and fill TCP checksum */
    hx_u16 tcp_cksum = hx_tcp_checksum(src_ip, dst_ip,
                                        tcp_seg, HX_TCP_HDR_LEN);
    memcpy(tcp_seg + 16, &tcp_cksum, 2);

    /* Build complete Eth+IP+TCP frame */
    hx_u32 frame_len = hx_net_build_frame(src_mac, dst_mac,
                                           src_ip, dst_ip,
                                           tcp_seg, HX_TCP_HDR_LEN,
                                           pkt_desc.data, pkt_desc.buf_len);
    if (frame_len == 0) {
        fprintf(stderr, "FAIL: hx_net_build_frame returned 0\n");
        hx_pktio_free_pkt(&io, &pkt_desc);
        hx_pktio_close(&io);
        hx_mempool_destroy(mp);
        return 1;
    }
    pkt_desc.len = frame_len;

    printf("  frame_len: %u bytes (Eth %d + IP %d + TCP %d)\n",
           frame_len, HX_ETHER_HDR_LEN, HX_IPV4_HDR_LEN, HX_TCP_HDR_LEN);

    /* 6. TX burst — send the SYN */
    hx_pkt_t *tx_pkts[1] = { &pkt_desc };
    int sent = hx_pktio_tx_burst(&io, tx_pkts, 1);
    if (sent != 1) {
        fprintf(stderr, "FAIL: tx_burst sent %d (expected 1)\n", sent);
        hx_pktio_free_pkt(&io, &pkt_desc);
        hx_pktio_close(&io);
        hx_mempool_destroy(mp);
        return 1;
    }
    printf("PASS: SYN frame sent (12345 → 80)\n");

    /* 7. Cleanup */
    hx_pktio_close(&io);
    printf("PASS: port closed\n");

    hx_mempool_destroy(mp);
    hx_dpdk_cleanup();
    printf("PASS: EAL cleaned up\n");

    printf("=== TX SMOKE PASSED ===\n");
    printf("\nVerify with tcpdump on peer:\n");
    printf("  tcpdump -i <iface> -nn 'tcp port 80 and tcp[tcpflags] == tcp-syn'\n");
    return 0;
}

#else /* !HX_USE_DPDK */

#include <stdio.h>

int main(void)
{
    fprintf(stderr, "This test requires HX_USE_DPDK. "
                    "Build with DPDK to run.\n");
    return 77; /* skip */
}

#endif
