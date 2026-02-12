#ifndef HURRICANE_MEMPOOL_H
#define HURRICANE_MEMPOOL_H

#include "common.h"

/*
 * Simple memory pool for packet buffers.
 *
 * In production, wraps DPDK rte_mempool.
 * For development, uses a basic free-list allocator.
 */

typedef struct hx_mempool hx_mempool_t;

/* Create a memory pool with `count` elements of `elem_size` bytes each */
hx_mempool_t *hx_mempool_create(const char *name, hx_u32 count, hx_u32 elem_size);

/* Destroy the memory pool and free all backing memory */
void hx_mempool_destroy(hx_mempool_t *mp);

/* Allocate one element from the pool. Returns NULL if empty. */
void *hx_mempool_alloc(hx_mempool_t *mp);

/* Return an element to the pool */
void hx_mempool_free(hx_mempool_t *mp, void *elem);

/* Get number of available elements */
hx_u32 hx_mempool_avail(const hx_mempool_t *mp);

#endif /* HURRICANE_MEMPOOL_H */
