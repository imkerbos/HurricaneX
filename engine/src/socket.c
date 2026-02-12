#include "hurricane/socket_table.h"
#include "hurricane/net.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Socket table implementation — O(1) lookup with pre-allocated sockets.
 *
 * All sockets are allocated in a single contiguous block for cache
 * friendliness. Each socket's 4-tuple is pre-assigned at init time.
 */

const char *hx_sk_state_str(enum hx_sk_state state)
{
    switch (state) {
    case HX_SK_CLOSED:       return "CLOSED";
    case HX_SK_SYN_SENT:     return "SYN_SENT";
    case HX_SK_SYN_RECEIVED: return "SYN_RECEIVED";
    case HX_SK_ESTABLISHED:  return "ESTABLISHED";
    case HX_SK_FIN_WAIT_1:   return "FIN_WAIT_1";
    case HX_SK_FIN_WAIT_2:   return "FIN_WAIT_2";
    case HX_SK_TIME_WAIT:    return "TIME_WAIT";
    case HX_SK_CLOSE_WAIT:   return "CLOSE_WAIT";
    case HX_SK_LAST_ACK:     return "LAST_ACK";
    default:                 return "UNKNOWN";
    }
}

/*
 * Compute partial TCP checksum for a socket's 4-tuple.
 *
 * The TCP pseudo-header checksum depends on src_ip, dst_ip, protocol,
 * and TCP length. Since src_ip/dst_ip are fixed per socket, we can
 * pre-compute the pseudo-header sum. At send time, we only need to
 * add the variable fields (seq, ack, flags) — but since the template
 * already has those zeroed, the partial checksum covers:
 *   pseudo-header + template TCP header + template payload
 *
 * For now we store a simple pseudo-header partial sum.
 * Full incremental checksum optimization comes in Phase 2 (mbuf_cache).
 */
static hx_u16 compute_pseudo_header_csum(hx_u32 laddr_n, hx_u32 faddr_n,
                                          hx_u16 tcp_len_n)
{
    hx_u32 sum = 0;

    /* Pseudo-header: src_ip + dst_ip + zero + proto + tcp_len */
    sum += (laddr_n >> 16) & 0xFFFF;
    sum += laddr_n & 0xFFFF;
    sum += (faddr_n >> 16) & 0xFFFF;
    sum += faddr_n & 0xFFFF;
    sum += hx_htons(HX_IP_PROTO_TCP);
    sum += tcp_len_n;

    /* Fold */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (hx_u16)sum;
}

struct hx_socket_table *hx_socket_table_create(
    hx_u32 laddr,
    hx_u16 lport_min, hx_u16 lport_max,
    hx_u32 faddr_min, hx_u32 faddr_max,
    hx_u16 fport_min, hx_u16 fport_max)
{
    if (lport_min > lport_max || fport_min > fport_max ||
        faddr_min > faddr_max)
        return NULL;

    hx_u32 lport_num = (hx_u32)(lport_max - lport_min + 1);
    hx_u32 faddr_num = faddr_max - faddr_min + 1;
    hx_u32 fport_num = (hx_u32)(fport_max - fport_min + 1);
    hx_u32 faddr_port_num = faddr_num * fport_num;
    hx_u64 total = (hx_u64)lport_num * faddr_port_num;

    if (total == 0 || total > 100000000ULL) /* sanity: max 100M sockets */
        return NULL;

    /* Allocate table */
    struct hx_socket_table *st = calloc(1, sizeof(*st));
    if (!st)
        return NULL;

    st->lport_min = lport_min;
    st->lport_max = lport_max;
    st->lport_num = (hx_u16)lport_num;
    st->faddr_min = faddr_min;
    st->faddr_max = faddr_max;
    st->faddr_num = faddr_num;
    st->fport_min = fport_min;
    st->fport_max = fport_max;
    st->fport_num = (hx_u16)fport_num;
    st->faddr_port_num = faddr_port_num;
    st->total_sockets = (hx_u32)total;

    /* Allocate socket pool — single contiguous block */
    size_t pool_size = sizeof(struct hx_socket_pool)
                     + (size_t)total * sizeof(struct hx_socket);
    st->pool = calloc(1, pool_size);
    if (!st->pool) {
        free(st);
        return NULL;
    }
    st->pool->num = (hx_u32)total;
    st->pool->next = 0;

    /* Allocate port table for this local IP */
    struct hx_socket_port_table *pt = calloc(1, sizeof(*pt));
    if (!pt) {
        free(st->pool);
        free(st);
        return NULL;
    }
    pt->sockets = st->pool->sockets;

    /* Register in hash table by laddr low 16 bits */
    hx_u16 laddr_low = laddr & 0xFFFF;
    st->ht[laddr_low] = pt;

    /* Initialize all sockets with their 4-tuples (network byte order) */
    hx_u32 laddr_n = hx_htonl(laddr);
    hx_u32 idx = 0;

    for (hx_u16 lp = lport_min; lp <= lport_max; lp++) {
        for (hx_u16 fp = fport_min; fp <= fport_max; fp++) {
            for (hx_u32 fa = faddr_min; fa <= faddr_max; fa++) {
                struct hx_socket *sk = &st->pool->sockets[idx];

                sk->state = HX_SK_CLOSED;
                sk->laddr = laddr_n;
                sk->faddr = hx_htonl(fa);
                sk->lport = hx_htons(lp);
                sk->fport = hx_htons(fp);

                /* Pre-compute pseudo-header checksum for each template size.
                 * TCP lengths: ACK=20, SYN=24(+MSS opt), DATA=20+payload.
                 * Actual values will be finalized in Phase 2 (mbuf_cache). */
                hx_u32 faddr_n = hx_htonl(fa);
                sk->csum_tcp = compute_pseudo_header_csum(
                    laddr_n, faddr_n, hx_htons(HX_TCP_HDR_LEN));
                sk->csum_tcp_opt = compute_pseudo_header_csum(
                    laddr_n, faddr_n, hx_htons(HX_TCP_HDR_LEN + 4));
                /* csum_tcp_data will be set when HTTP payload size is known */
                sk->csum_tcp_data = 0;

                idx++;

                if (lp == lport_max && fp == fport_max && fa == faddr_max)
                    goto done;
            }
        }
    }

done:
    return st;
}

void hx_socket_table_destroy(struct hx_socket_table *st)
{
    if (!st)
        return;

    /* Free all port tables */
    for (int i = 0; i < 65536; i++) {
        if (st->ht[i]) {
            free(st->ht[i]);
            st->ht[i] = NULL;
        }
    }

    free(st->pool);
    free(st);
}
