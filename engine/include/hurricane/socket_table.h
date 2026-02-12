#ifndef HURRICANE_SOCKET_TABLE_H
#define HURRICANE_SOCKET_TABLE_H

#include "socket.h"
#include "net.h"

/*
 * O(1) socket lookup table — inspired by dperf.
 *
 * All sockets are pre-allocated at init time in a contiguous array.
 * Lookup is a direct array index computation from the 4-tuple:
 *
 *   idx = (lport - lport_min) * faddr_port_num
 *       + (fport - fport_min) * faddr_num
 *       + (faddr - faddr_min)
 *
 * No hash, no collision, no linked list. O(1) deterministic.
 *
 * Terminology (client mode):
 *   laddr/lport = local (source) address/port
 *   faddr/fport = foreign (destination) address/port
 */

/* Per-local-IP socket array */
struct hx_socket_port_table {
    struct hx_socket *sockets;   /* indexed by computed offset */
};

/* Socket pool — contiguous pre-allocated sockets */
struct hx_socket_pool {
    hx_u32  num;                 /* total sockets */
    hx_u32  next;                /* next socket index to launch */
    struct hx_socket sockets[];  /* flexible array member */
};

/* Socket table — top-level lookup structure */
struct hx_socket_table {
    /* Foreign (destination) IP range — host byte order */
    hx_u32  faddr_min;
    hx_u32  faddr_max;
    hx_u32  faddr_num;           /* faddr_max - faddr_min + 1 */

    /* Foreign (destination) port range — host byte order */
    hx_u16  fport_min;
    hx_u16  fport_max;
    hx_u16  fport_num;           /* fport_max - fport_min + 1 */

    /* Local (source) port range — host byte order */
    hx_u16  lport_min;
    hx_u16  lport_max;
    hx_u16  lport_num;           /* lport_max - lport_min + 1 */

    /* Pre-computed: faddr_num * fport_num */
    hx_u32  faddr_port_num;

    /* Total socket count = lport_num * faddr_port_num */
    hx_u32  total_sockets;

    /* Hash table: indexed by laddr low 16 bits */
    struct hx_socket_port_table *ht[65536];

    /* Socket pool (all sockets live here) */
    struct hx_socket_pool *pool;
};

/*
 * Create and initialize socket table.
 *
 * Allocates all sockets upfront. Each socket gets its 4-tuple
 * pre-assigned and partial checksums pre-computed.
 *
 * Parameters (all in host byte order):
 *   laddr      — local IP address
 *   lport_min/max — local port range
 *   faddr_min/max — foreign IP range (single IP: min == max)
 *   fport_min/max — foreign port range (single port: min == max)
 */
struct hx_socket_table *hx_socket_table_create(
    hx_u32 laddr,
    hx_u16 lport_min, hx_u16 lport_max,
    hx_u32 faddr_min, hx_u32 faddr_max,
    hx_u16 fport_min, hx_u16 fport_max);

/* Destroy socket table and free all memory */
void hx_socket_table_destroy(struct hx_socket_table *st);

/*
 * O(1) socket lookup by 4-tuple (network byte order).
 * Returns NULL if out of range.
 */
static inline struct hx_socket *hx_socket_lookup(
    const struct hx_socket_table *st,
    hx_u32 laddr_n, hx_u16 lport_n,
    hx_u32 faddr_n, hx_u16 fport_n)
{
    hx_u16 laddr_low = hx_ntohl(laddr_n) & 0xFFFF;
    struct hx_socket_port_table *pt = st->ht[laddr_low];
    if (!pt)
        return NULL;

    hx_u16 lport = hx_ntohs(lport_n);
    hx_u16 fport = hx_ntohs(fport_n);
    hx_u32 faddr = hx_ntohl(faddr_n);

    /* Bounds check */
    if (lport < st->lport_min || lport > st->lport_max ||
        fport < st->fport_min || fport > st->fport_max ||
        faddr < st->faddr_min || faddr > st->faddr_max)
        return NULL;

    hx_u32 idx = (hx_u32)(lport - st->lport_min) * st->faddr_port_num
               + (hx_u32)(fport - st->fport_min) * st->faddr_num
               + (faddr - st->faddr_min);

    return &pt->sockets[idx];
}

/*
 * Get next socket to launch (for client_launch).
 * Returns NULL when all sockets have been launched.
 */
static inline struct hx_socket *hx_socket_table_next(
    struct hx_socket_table *st)
{
    if (!st->pool || st->pool->next >= st->pool->num)
        return NULL;
    return &st->pool->sockets[st->pool->next++];
}

/* Reset launch index (for re-running) */
static inline void hx_socket_table_reset_launch(
    struct hx_socket_table *st)
{
    if (st->pool)
        st->pool->next = 0;
}

/* Get total socket count */
static inline hx_u32 hx_socket_table_count(
    const struct hx_socket_table *st)
{
    return st->pool ? st->pool->num : 0;
}

#endif /* HURRICANE_SOCKET_TABLE_H */
