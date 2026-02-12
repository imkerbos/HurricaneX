#include "hurricane/mempool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Simple free-list memory pool.
 */

struct hx_mempool {
    char    name[64];
    hx_u32  elem_size;
    hx_u32  count;
    hx_u32  avail;
    void  **free_list;
    hx_u8  *backing;    /* contiguous backing memory */
};

hx_mempool_t *hx_mempool_create(const char *name, hx_u32 count, hx_u32 elem_size)
{
    if (count == 0 || elem_size == 0)
        return NULL;

    hx_mempool_t *mp = calloc(1, sizeof(*mp));
    if (!mp)
        return NULL;

    snprintf(mp->name, sizeof(mp->name), "%s", name);
    mp->elem_size = elem_size;
    mp->count = count;
    mp->avail = count;

    mp->backing = calloc(count, elem_size);
    if (!mp->backing) {
        free(mp);
        return NULL;
    }

    mp->free_list = calloc(count, sizeof(void *));
    if (!mp->free_list) {
        free(mp->backing);
        free(mp);
        return NULL;
    }

    /* Populate free list */
    for (hx_u32 i = 0; i < count; i++) {
        mp->free_list[i] = mp->backing + (i * elem_size);
    }

    return mp;
}

void hx_mempool_destroy(hx_mempool_t *mp)
{
    if (!mp)
        return;
    free(mp->free_list);
    free(mp->backing);
    free(mp);
}

void *hx_mempool_alloc(hx_mempool_t *mp)
{
    if (!mp || mp->avail == 0)
        return NULL;

    mp->avail--;
    return mp->free_list[mp->avail];
}

void hx_mempool_free(hx_mempool_t *mp, void *elem)
{
    if (!mp || !elem)
        return;
    if (mp->avail >= mp->count)
        return; /* pool is full, double-free guard */

    mp->free_list[mp->avail] = elem;
    mp->avail++;
}

hx_u32 hx_mempool_avail(const hx_mempool_t *mp)
{
    if (!mp)
        return 0;
    return mp->avail;
}
