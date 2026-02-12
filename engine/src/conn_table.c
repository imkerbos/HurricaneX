#include "hurricane/conn_table.h"
#include <stdlib.h>
#include <string.h>

/*
 * Connection table — open-addressing hash map with linear probing.
 *
 * Capacity is always a power of 2 so we can use mask instead of modulo.
 * Load factor should stay below ~75% for good performance.
 */

/* Round up to next power of 2 */
static hx_u32 next_pow2(hx_u32 v)
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v < 16 ? 16 : v;
}

/* FNV-1a inspired hash for 4-tuple */
hx_u32 hx_conn_hash(hx_u32 src_ip, hx_u16 src_port,
                     hx_u32 dst_ip, hx_u16 dst_port)
{
    hx_u32 h = 2166136261u;
    h ^= src_ip;
    h *= 16777619u;
    h ^= (hx_u32)src_port;
    h *= 16777619u;
    h ^= dst_ip;
    h *= 16777619u;
    h ^= (hx_u32)dst_port;
    h *= 16777619u;
    return h;
}

hx_conn_table_t *hx_conn_table_create(hx_u32 capacity)
{
    capacity = next_pow2(capacity);

    hx_conn_table_t *ct = calloc(1, sizeof(*ct));
    if (!ct)
        return NULL;

    ct->slots = calloc(capacity, sizeof(hx_conn_slot_t));
    if (!ct->slots) {
        free(ct);
        return NULL;
    }

    ct->capacity = capacity;
    ct->count = 0;
    return ct;
}

void hx_conn_table_destroy(hx_conn_table_t *ct)
{
    if (!ct)
        return;
    free(ct->slots);
    free(ct);
}

static int slot_matches(const hx_conn_slot_t *s,
                        hx_u32 src_ip, hx_u16 src_port,
                        hx_u32 dst_ip, hx_u16 dst_port)
{
    if (s->state != HX_CONN_SLOT_USED)
        return 0;
    const hx_tcp_conn_t *c = &s->conn;
    return c->src_ip == src_ip && c->src_port == src_port &&
           c->dst_ip == dst_ip && c->dst_port == dst_port;
}

hx_tcp_conn_t *hx_conn_table_insert(hx_conn_table_t *ct,
                                     hx_u32 src_ip, hx_u16 src_port,
                                     hx_u32 dst_ip, hx_u16 dst_port,
                                     hx_pktio_t *pktio,
                                     const hx_u8 src_mac[6],
                                     const hx_u8 dst_mac[6])
{
    if (!ct || ct->count >= ct->capacity * 3 / 4)
        return NULL; /* load factor > 75% */

    hx_u32 h = hx_conn_hash(src_ip, src_port, dst_ip, dst_port);
    hx_u32 mask = ct->capacity - 1;
    hx_u32 idx = h & mask;

    for (hx_u32 i = 0; i < ct->capacity; i++) {
        hx_conn_slot_t *s = &ct->slots[idx];

        if (s->state == HX_CONN_SLOT_EMPTY) {
            /* Found empty slot — insert here */
            s->state = HX_CONN_SLOT_USED;
            s->hash = h;

            hx_tcp_conn_t *c = &s->conn;
            hx_tcp_init(c, pktio);
            c->src_ip = src_ip;
            c->src_port = src_port;
            c->dst_ip = dst_ip;
            c->dst_port = dst_port;
            if (src_mac)
                memcpy(c->src_mac, src_mac, 6);
            if (dst_mac)
                memcpy(c->dst_mac, dst_mac, 6);

            ct->count++;
            return c;
        }

        /* Duplicate check */
        if (slot_matches(s, src_ip, src_port, dst_ip, dst_port))
            return NULL; /* already exists */

        idx = (idx + 1) & mask;
    }

    return NULL; /* table full (shouldn't happen with 75% check) */
}

hx_tcp_conn_t *hx_conn_table_lookup(hx_conn_table_t *ct,
                                     hx_u32 src_ip, hx_u16 src_port,
                                     hx_u32 dst_ip, hx_u16 dst_port)
{
    if (!ct || ct->count == 0)
        return NULL;

    hx_u32 h = hx_conn_hash(src_ip, src_port, dst_ip, dst_port);
    hx_u32 mask = ct->capacity - 1;
    hx_u32 idx = h & mask;

    for (hx_u32 i = 0; i < ct->capacity; i++) {
        hx_conn_slot_t *s = &ct->slots[idx];

        if (s->state == HX_CONN_SLOT_EMPTY)
            return NULL; /* not found */

        if (slot_matches(s, src_ip, src_port, dst_ip, dst_port))
            return &s->conn;

        idx = (idx + 1) & mask;
    }

    return NULL;
}

hx_result_t hx_conn_table_remove(hx_conn_table_t *ct,
                                  hx_u32 src_ip, hx_u16 src_port,
                                  hx_u32 dst_ip, hx_u16 dst_port)
{
    if (!ct || ct->count == 0)
        return HX_ERR_INVAL;

    hx_u32 h = hx_conn_hash(src_ip, src_port, dst_ip, dst_port);
    hx_u32 mask = ct->capacity - 1;
    hx_u32 idx = h & mask;

    for (hx_u32 i = 0; i < ct->capacity; i++) {
        hx_conn_slot_t *s = &ct->slots[idx];

        if (s->state == HX_CONN_SLOT_EMPTY)
            return HX_ERR_INVAL;

        if (slot_matches(s, src_ip, src_port, dst_ip, dst_port)) {
            /*
             * Deletion with linear probing: need to rehash subsequent
             * entries to maintain probe chains. Simple approach: mark
             * empty and re-insert displaced entries.
             */
            s->state = HX_CONN_SLOT_EMPTY;
            ct->count--;

            /* Rehash subsequent entries until we hit an empty slot */
            hx_u32 next = (idx + 1) & mask;
            while (ct->slots[next].state == HX_CONN_SLOT_USED) {
                hx_conn_slot_t tmp = ct->slots[next];
                ct->slots[next].state = HX_CONN_SLOT_EMPTY;
                ct->count--;

                /* Re-insert */
                hx_u32 rh = tmp.hash;
                hx_u32 ri = rh & mask;
                while (ct->slots[ri].state == HX_CONN_SLOT_USED)
                    ri = (ri + 1) & mask;
                ct->slots[ri] = tmp;
                ct->count++;

                next = (next + 1) & mask;
            }

            return HX_OK;
        }

        idx = (idx + 1) & mask;
    }

    return HX_ERR_INVAL;
}

hx_u32 hx_conn_table_count(const hx_conn_table_t *ct)
{
    return ct ? ct->count : 0;
}
