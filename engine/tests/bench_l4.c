/*
 * L4 TCP benchmark — DPDK-based TCP handshake test.
 *
 * Creates N connections to a target, completes 3-way handshake,
 * then closes. Measures CPS (connections per second).
 *
 * Usage:
 *   ./bench_l4 --lcores 0 -a <PCI> -- <dst_mac> <src_ip> <dst_ip> [dst_port] [num_conns] [duration_sec]
 *
 * Example:
 *   ./bench_l4 --lcores 0 -a 7f:00.0 -- 06:bd:69:51:fc:e5 172.31.34.0 172.31.36.171 80 100 10
 */
#ifdef HX_USE_DPDK

#include "hurricane/dpdk.h"
#include "hurricane/work_space.h"
#include "hurricane/mempool.h"
#include "hurricane/log.h"

#include <rte_ethdev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static void print_stats(const struct hx_ws_stats *s)
{
    printf("\n=== Results ===\n");
    printf("  elapsed:       %.3f sec\n", s->elapsed_sec);
    printf("  attempted:     %llu\n", (unsigned long long)s->conns_attempted);
    printf("  established:   %llu\n", (unsigned long long)s->conns_established);
    printf("  closed:        %llu\n", (unsigned long long)s->conns_closed);
    printf("  reset:         %llu\n", (unsigned long long)s->conns_reset);
    printf("  failed:        %llu\n", (unsigned long long)s->conns_failed);
    printf("  retransmit:    %llu\n", (unsigned long long)s->conns_retransmit);
    printf("  pkts_tx:       %llu\n", (unsigned long long)s->pkts_tx);
    printf("  pkts_rx:       %llu\n", (unsigned long long)s->pkts_rx);
    printf("  rx_loop_iters: %llu\n", (unsigned long long)s->rx_loop_iters);
    if (s->elapsed_sec > 0 && s->conns_established > 0) {
        printf("  CPS:           %.0f\n",
               (double)s->conns_established / s->elapsed_sec);
    }
}

int main(int argc, char **argv)
{
    printf("=== HurricaneX L4 TCP Benchmark ===\n");

    /* Split EAL / app args */
    int eal_argc = argc;
    int app_argc = 0;
    char **app_argv = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            eal_argc = i;
            app_argc = argc - i - 1;
            app_argv = &argv[i + 1];
            break;
        }
    }

    /* EAL init */
    hx_dpdk_config_t dpdk_cfg = { .argc = eal_argc, .argv = argv };
    hx_result_t rc = hx_dpdk_init(&dpdk_cfg);
    if (rc != HX_OK) {
        fprintf(stderr, "FAIL: hx_dpdk_init: %s\n", hx_strerror(rc));
        return 1;
    }

    /* Parse app args */
    if (app_argc < 3) {
        fprintf(stderr, "Usage: %s <EAL args> -- <dst_mac> <src_ip> <dst_ip>"
                        " [dst_port] [num_conns] [duration_sec]\n", argv[0]);
        return 1;
    }

    struct hx_ws_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    srand((unsigned)time(NULL));
    cfg.src_port_base = (hx_u16)(10000 + (rand() % 40000));
    cfg.dst_port = 80;
    cfg.num_conns = 10;
    cfg.duration_sec = 10;
    cfg.launch_batch = 64;

    if (parse_mac(app_argv[0], cfg.dst_mac) != 0) {
        fprintf(stderr, "FAIL: invalid dst_mac '%s'\n", app_argv[0]);
        return 1;
    }
    if (parse_ipv4(app_argv[1], &cfg.src_ip) != 0) {
        fprintf(stderr, "FAIL: invalid src_ip '%s'\n", app_argv[1]);
        return 1;
    }
    if (parse_ipv4(app_argv[2], &cfg.dst_ip) != 0) {
        fprintf(stderr, "FAIL: invalid dst_ip '%s'\n", app_argv[2]);
        return 1;
    }
    if (app_argc >= 4)
        cfg.dst_port = (hx_u16)atoi(app_argv[3]);
    if (app_argc >= 5)
        cfg.num_conns = (hx_u32)atoi(app_argv[4]);
    if (app_argc >= 6)
        cfg.duration_sec = (hx_u32)atoi(app_argv[5]);

    printf("  dst_mac:    %02x:%02x:%02x:%02x:%02x:%02x\n",
           cfg.dst_mac[0], cfg.dst_mac[1], cfg.dst_mac[2],
           cfg.dst_mac[3], cfg.dst_mac[4], cfg.dst_mac[5]);
    printf("  src_ip:     %u.%u.%u.%u\n",
           (cfg.src_ip >> 24) & 0xFF, (cfg.src_ip >> 16) & 0xFF,
           (cfg.src_ip >> 8) & 0xFF, cfg.src_ip & 0xFF);
    printf("  dst_ip:     %u.%u.%u.%u\n",
           (cfg.dst_ip >> 24) & 0xFF, (cfg.dst_ip >> 16) & 0xFF,
           (cfg.dst_ip >> 8) & 0xFF, cfg.dst_ip & 0xFF);
    printf("  dst_port:   %u\n", cfg.dst_port);
    printf("  src_ports:  %u..%u\n", cfg.src_port_base,
           cfg.src_port_base + cfg.num_conns - 1);
    printf("  num_conns:  %u\n", cfg.num_conns);
    printf("  duration:   %u sec\n", cfg.duration_sec);

    /* Mempool + pktio */
    hx_mempool_t *mp = hx_mempool_create("bench", 256, 2048);
    if (!mp) {
        fprintf(stderr, "FAIL: hx_mempool_create\n");
        return 1;
    }

    hx_pktio_t io;
    rc = hx_pktio_init(&io, &hx_pktio_dpdk_ops, "dpdk:0", mp);
    if (rc != HX_OK) {
        fprintf(stderr, "FAIL: hx_pktio_init: %s\n", hx_strerror(rc));
        hx_mempool_destroy(mp);
        return 1;
    }

    /* Get port MAC */
    struct rte_ether_addr port_mac;
    if (rte_eth_macaddr_get(0, &port_mac) == 0)
        memcpy(cfg.src_mac, port_mac.addr_bytes, 6);

    printf("  src_mac:    %02x:%02x:%02x:%02x:%02x:%02x\n",
           cfg.src_mac[0], cfg.src_mac[1], cfg.src_mac[2],
           cfg.src_mac[3], cfg.src_mac[4], cfg.src_mac[5]);

    /* Work space init + run */
    struct hx_work_space ws;
    rc = hx_ws_init(&ws, &io, &cfg);
    if (rc != HX_OK) {
        fprintf(stderr, "FAIL: hx_ws_init: %s\n", hx_strerror(rc));
        hx_pktio_close(&io);
        hx_mempool_destroy(mp);
        return 1;
    }

    printf("\nStarting benchmark...\n");
    hx_ws_run(&ws);

    /* Print results */
    struct hx_ws_stats stats = hx_ws_get_stats(&ws);
    print_stats(&stats);

    /* Cleanup */
    hx_ws_cleanup(&ws);
    hx_pktio_close(&io);
    hx_mempool_destroy(mp);
    hx_dpdk_cleanup();

    printf("=== DONE ===\n");
    return 0;
}

#else /* !HX_USE_DPDK */

#include <stdio.h>

int main(void)
{
    fprintf(stderr, "This benchmark requires HX_USE_DPDK. "
                    "Build with DPDK to run.\n");
    return 77;
}

#endif
