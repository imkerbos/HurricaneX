#ifndef HURRICANE_CONN_TABLE_H
#define HURRICANE_CONN_TABLE_H

#include "common.h"
#include "tcp.h"

/*
 * Connection table — fixed-size hash map for TCP connection lookup.
 *
 * Pre-allocates a pool of hx_tcp_conn_t entries. Connections are
 * indexed by a 4-tuple hash (src_ip, src_port, dst_ip, dst_port)
 * for O(1) lookup on the RX path.
 *
 * Collision handling: open addressing with linear probing.
 */

/* Connection entry states */
#define HX_CONN_SLOT_EMPTY  0
#define HX_CONN_SLOT_USED   1

typedef struct hx_conn_slot {
    hx_u8          state;    /* EMPTY or USED */
    hx_u32         hash;     /* cached hash for faster reprobing */
    hx_tcp_conn_t  conn;
} hx_conn_slot_t;

typedef struct hx_conn_table {
    hx_conn_slot_t *slots;
    hx_u32          capacity;  /* must be power of 2 */
    hx_u32          count;     /* number of USED slots */
} hx_conn_table_t;

/*
 * Create a connection table with the given capacity (rounded up to power of 2).
 * Returns NULL on allocation failure.
 */
hx_conn_table_t *hx_conn_table_create(hx_u32 capacity);

/* Destroy a connection table and free all memory. */
void hx_conn_table_destroy(hx_conn_table_t *ct);

/*
 * Insert a new connection. Initializes the conn with pktio, sets
 * src/dst addresses and MACs. Returns pointer to the inserted
 * hx_tcp_conn_t, or NULL if table is full.
 */
hx_tcp_conn_t *hx_conn_table_insert(hx_conn_table_t *ct,
                                     hx_u32 src_ip, hx_u16 src_port,
                                     hx_u32 dst_ip, hx_u16 dst_port,
                                     hx_pktio_t *pktio,
                                     const hx_u8 src_mac[6],
                                     const hx_u8 dst_mac[6]);

/*
 * Lookup a connection by 4-tuple.
 * Returns pointer to hx_tcp_conn_t, or NULL if not found.
 */
hx_tcp_conn_t *hx_conn_table_lookup(hx_conn_table_t *ct,
                                     hx_u32 src_ip, hx_u16 src_port,
                                     hx_u32 dst_ip, hx_u16 dst_port);

/*
 * Remove a connection by 4-tuple.
 * Returns HX_OK if removed, HX_ERR_INVAL if not found.
 */
hx_result_t hx_conn_table_remove(hx_conn_table_t *ct,
                                  hx_u32 src_ip, hx_u16 src_port,
                                  hx_u32 dst_ip, hx_u16 dst_port);

/* Current number of active connections. */
hx_u32 hx_conn_table_count(const hx_conn_table_t *ct);

/* Compute 4-tuple hash (exposed for testing). */
hx_u32 hx_conn_hash(hx_u32 src_ip, hx_u16 src_port,
                     hx_u32 dst_ip, hx_u16 dst_port);

#endif /* HURRICANE_CONN_TABLE_H */
