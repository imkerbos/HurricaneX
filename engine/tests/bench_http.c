/*
 * L7 HTTP benchmark — DPDK-based HTTP request test.
 *
 * Usage:
 *   ./bench_http <EAL args> -- [options]
 *
 * Options:
 *   -m <mac>       Gateway MAC (required)
 *   -s <ip>        Source IP (required)
 *   -u <url>       Target URL: http://host[:port]/path (required)
 *   -H <header>    Extra header, e.g. "Referer: http://example.com/"
 *   -n <num>       Number of connections (default: 10)
 *   -d <sec>       Duration in seconds (default: 10)
 *
 * Example:
 *   ./bench_http --lcores 0 -a 7f:00.0 -- \
 *       -m 06:dd:30:51:0d:3d -s 172.31.34.0 \
 *       -u "http://uat-game.p3-uat.click/api/v1/activity/list" \
 *       -H "Referer: http://uat-game.p3-uat.click/" \
 *       -n 10 -d 30
 */
#ifdef HX_USE_DPDK

#include "hurricane/dpdk.h"
#include "hurricane/engine.h"
#include "hurricane/mempool.h"
#include "hurricane/log.h"

#include <rte_ethdev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>

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

/*
 * Resolve hostname or IPv4 string to a 32-bit IP (host byte order).
 * Tries parse_ipv4 first, falls back to getaddrinfo for DNS.
 */
static int resolve_host(const char *str, hx_u32 *ip)
{
    if (parse_ipv4(str, ip) == 0)
        return 0;

    /* DNS lookup */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(str, NULL, &hints, &res);
    if (ret != 0 || !res) {
        fprintf(stderr, "DNS resolve failed for '%s': %s\n",
                str, gai_strerror(ret));
        return -1;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    uint32_t nip = ntohl(addr->sin_addr.s_addr);
    *ip = nip;

    printf("  resolved:   %s -> %u.%u.%u.%u\n", str,
           (nip >> 24) & 0xFF, (nip >> 16) & 0xFF,
           (nip >> 8) & 0xFF, nip & 0xFF);

    freeaddrinfo(res);
    return 0;
}

static void print_stats(const hx_engine_stats_t *s)
{
    printf("\n=== Results ===\n");
    printf("  elapsed:       %.3f sec\n", s->elapsed_sec);
    printf("  attempted:     %llu\n", (unsigned long long)s->conns_attempted);
    printf("  established:   %llu\n", (unsigned long long)s->conns_established);
    printf("  closed:        %llu\n", (unsigned long long)s->conns_closed);
    printf("  reset:         %llu\n", (unsigned long long)s->conns_reset);
    printf("  failed:        %llu\n", (unsigned long long)s->conns_failed);
    printf("  retransmit:    %llu\n", (unsigned long long)s->conns_retransmit);
    printf("  http_req:      %llu\n", (unsigned long long)s->http_req_sent);
    printf("  http_resp:     %llu\n", (unsigned long long)s->http_resp_recv);
    printf("  http_2xx:      %llu\n", (unsigned long long)s->http_resp_2xx);
    printf("  http_other:    %llu\n", (unsigned long long)s->http_resp_other);
    printf("  pkts_tx:       %llu\n", (unsigned long long)s->pkts_tx);
    printf("  pkts_rx:       %llu\n", (unsigned long long)s->pkts_rx);
    printf("  rx_loop_iters: %llu\n", (unsigned long long)s->rx_loop_iters);
    if (s->elapsed_sec > 0 && s->http_resp_recv > 0) {
        printf("  RPS:           %.0f\n",
               (double)s->http_resp_recv / s->elapsed_sec);
    }
    if (s->elapsed_sec > 0 && s->conns_established > 0) {
        printf("  CPS:           %.0f\n",
               (double)s->conns_established / s->elapsed_sec);
    }
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <EAL args> -- [options]\n"
        "  -m <mac>       Gateway MAC (required)\n"
        "  -s <ip>        Source IP (required)\n"
        "  -u <url>       Target URL: http://host[:port]/path (required)\n"
        "  -H <header>    Extra header (repeatable)\n"
        "  -n <num>       Number of connections (default: 10)\n"
        "  -d <sec>       Duration in seconds (default: 10)\n"
        "  -k <num>       Requests per connection (default: 1, 0=unlimited)\n",
        prog);
}

/*
 * Parse URL: "http://host[:port][/path]"
 * Fills host, port, path. Returns 0 on success.
 */
static int parse_url(const char *url, char *host, size_t host_sz,
                     hx_u16 *port, char *path, size_t path_sz)
{
    const char *p = url;

    /* Skip scheme */
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        *port = 80;
    } else if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        *port = 443;
    } else {
        *port = 80;
    }

    /* Find end of host (: or / or end) */
    const char *host_start = p;
    while (*p && *p != ':' && *p != '/')
        p++;

    size_t hlen = (size_t)(p - host_start);
    if (hlen == 0 || hlen >= host_sz)
        return -1;
    memcpy(host, host_start, hlen);
    host[hlen] = '\0';

    /* Optional port */
    if (*p == ':') {
        p++;
        *port = (hx_u16)atoi(p);
        while (*p && *p != '/')
            p++;
    }

    /* Path */
    if (*p == '/') {
        snprintf(path, path_sz, "%s", p);
    } else {
        snprintf(path, path_sz, "/");
    }

    return 0;
}

int main(int argc, char **argv)
{
    printf("=== HurricaneX L7 HTTP Benchmark ===\n");

    /*
     * Split argv into EAL args and app args at "--".
     * Deep-copy app args because rte_eal_init() may modify the
     * original argv array (including entries after eal_argc).
     */
    int eal_argc = argc;
    int app_argc = 0;
    char *app_args[64];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            eal_argc = i;
            for (int j = i + 1; j < argc && app_argc < 64; j++) {
                size_t len = strlen(argv[j]) + 1;
                app_args[app_argc] = malloc(len);
                memcpy(app_args[app_argc], argv[j], len);
                app_argc++;
            }
            break;
        }
    }

    /* Build a separate argv for EAL so it can't touch our app args */
    char *eal_argv[64];
    for (int i = 0; i < eal_argc && i < 64; i++)
        eal_argv[i] = argv[i];
    eal_argv[eal_argc] = NULL;

    /* EAL init — use separate eal_argv */
    hx_dpdk_config_t dpdk_cfg = { .argc = eal_argc, .argv = eal_argv };
    hx_result_t rc = hx_dpdk_init(&dpdk_cfg);
    if (rc != HX_OK) {
        fprintf(stderr, "FAIL: hx_dpdk_init: %s\n", hx_strerror(rc));
        return 1;
    }

    /* Parse app args: flag style */
    hx_engine_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    srand((unsigned)time(NULL));
    cfg.src_port_base = (hx_u16)(10000 + (rand() % 40000));
    cfg.dst_port = 80;
    cfg.num_conns = 10;
    cfg.duration_sec = 10;
    cfg.http_enabled = true;
    cfg.http_method = HX_HTTP_GET;
    cfg.http_requests_per_conn = 1;
    snprintf(cfg.http_path, sizeof(cfg.http_path), "/");

    int got_mac = 0, got_src = 0, got_url = 0;
    int headers_off = 0; /* offset into http_extra_headers */

    for (int i = 0; i < app_argc; i++) {
        if (strcmp(app_args[i], "-m") == 0 && i + 1 < app_argc) {
            if (parse_mac(app_args[++i], cfg.dst_mac) != 0) {
                fprintf(stderr, "FAIL: invalid MAC '%s'\n", app_args[i]);
                return 1;
            }
            got_mac = 1;
        } else if (strcmp(app_args[i], "-s") == 0 && i + 1 < app_argc) {
            if (parse_ipv4(app_args[++i], &cfg.src_ip) != 0) {
                fprintf(stderr, "FAIL: invalid src_ip '%s'\n", app_args[i]);
                return 1;
            }
            got_src = 1;
        } else if (strcmp(app_args[i], "-u") == 0 && i + 1 < app_argc) {
            char host[256];
            if (parse_url(app_args[++i], host, sizeof(host),
                          &cfg.dst_port, cfg.http_path,
                          sizeof(cfg.http_path)) != 0) {
                fprintf(stderr, "FAIL: invalid URL '%s'\n", app_args[i]);
                return 1;
            }
            /* Resolve host to IP */
            if (resolve_host(host, &cfg.dst_ip) != 0) {
                fprintf(stderr, "FAIL: cannot resolve '%s'\n", host);
                return 1;
            }
            /* Set Host header */
            snprintf(cfg.http_host, sizeof(cfg.http_host), "%s", host);
            got_url = 1;
        } else if (strcmp(app_args[i], "-H") == 0 && i + 1 < app_argc) {
            i++;
            int w = snprintf(cfg.http_extra_headers + headers_off,
                             sizeof(cfg.http_extra_headers) - headers_off,
                             "%s\r\n", app_args[i]);
            if (w > 0)
                headers_off += w;
        } else if (strcmp(app_args[i], "-n") == 0 && i + 1 < app_argc) {
            cfg.num_conns = (hx_u32)atoi(app_args[++i]);
        } else if (strcmp(app_args[i], "-d") == 0 && i + 1 < app_argc) {
            cfg.duration_sec = (hx_u32)atoi(app_args[++i]);
        } else if (strcmp(app_args[i], "-k") == 0 && i + 1 < app_argc) {
            cfg.http_requests_per_conn = (hx_u32)atoi(app_args[++i]);
        } else {
            fprintf(stderr, "Unknown option: %s\n", app_args[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!got_mac || !got_src || !got_url) {
        fprintf(stderr, "Missing required options: %s%s%s\n",
                got_mac ? "" : "-m ",
                got_src ? "" : "-s ",
                got_url ? "" : "-u ");
        print_usage(argv[0]);
        return 1;
    }

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
    printf("  http_host:  %s\n", cfg.http_host);
    printf("  http_path:  %s\n", cfg.http_path);
    if (cfg.http_extra_headers[0])
        printf("  headers:    %.*s\n",
               (int)(strlen(cfg.http_extra_headers) - 2),
               cfg.http_extra_headers); /* trim trailing \r\n */
    printf("  keep-alive: %s\n",
           cfg.http_requests_per_conn == 1 ? "off" :
           cfg.http_requests_per_conn == 0 ? "unlimited" : "on");
    if (cfg.http_requests_per_conn > 1)
        printf("  reqs/conn:  %u\n", cfg.http_requests_per_conn);

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

    /* Engine init + start + run */
    hx_engine_t eng;
    rc = hx_engine_init(&eng, &io, &cfg);
    if (rc != HX_OK) {
        fprintf(stderr, "FAIL: hx_engine_init: %s\n", hx_strerror(rc));
        hx_pktio_close(&io);
        hx_mempool_destroy(mp);
        return 1;
    }

    printf("\nStarting HTTP benchmark...\n");
    rc = hx_engine_start(&eng);
    if (rc != HX_OK) {
        fprintf(stderr, "FAIL: hx_engine_start: %s\n", hx_strerror(rc));
        hx_engine_cleanup(&eng);
        hx_pktio_close(&io);
        hx_mempool_destroy(mp);
        return 1;
    }

    hx_engine_run(&eng);

    /* Print results */
    hx_engine_stats_t stats = hx_engine_get_stats(&eng);
    print_stats(&stats);

    /* Cleanup */
    hx_engine_cleanup(&eng);
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
