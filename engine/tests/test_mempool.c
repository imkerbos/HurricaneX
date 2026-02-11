#include "hurricane/mempool.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_create_destroy(void)
{
    hx_mempool_t *mp = hx_mempool_create("test", 16, 64);
    assert(mp != NULL);
    assert(hx_mempool_avail(mp) == 16);
    hx_mempool_destroy(mp);
    printf("  PASS: test_create_destroy\n");
}

static void test_create_invalid(void)
{
    assert(hx_mempool_create("bad", 0, 64) == NULL);
    assert(hx_mempool_create("bad", 16, 0) == NULL);
    printf("  PASS: test_create_invalid\n");
}

static void test_alloc_free(void)
{
    hx_mempool_t *mp = hx_mempool_create("test", 4, 128);
    assert(mp != NULL);

    void *a = hx_mempool_alloc(mp);
    void *b = hx_mempool_alloc(mp);
    assert(a != NULL);
    assert(b != NULL);
    assert(a != b);
    assert(hx_mempool_avail(mp) == 2);

    hx_mempool_free(mp, a);
    assert(hx_mempool_avail(mp) == 3);

    hx_mempool_free(mp, b);
    assert(hx_mempool_avail(mp) == 4);

    hx_mempool_destroy(mp);
    printf("  PASS: test_alloc_free\n");
}

static void test_exhaust_pool(void)
{
    hx_mempool_t *mp = hx_mempool_create("test", 3, 32);
    assert(mp != NULL);

    void *a = hx_mempool_alloc(mp);
    void *b = hx_mempool_alloc(mp);
    void *c = hx_mempool_alloc(mp);
    assert(a && b && c);
    assert(hx_mempool_avail(mp) == 0);

    /* Pool exhausted — should return NULL */
    assert(hx_mempool_alloc(mp) == NULL);

    /* Free one and alloc again */
    hx_mempool_free(mp, b);
    assert(hx_mempool_avail(mp) == 1);
    void *d = hx_mempool_alloc(mp);
    assert(d != NULL);
    assert(hx_mempool_avail(mp) == 0);

    hx_mempool_free(mp, a);
    hx_mempool_free(mp, c);
    hx_mempool_free(mp, d);
    hx_mempool_destroy(mp);
    printf("  PASS: test_exhaust_pool\n");
}

static void test_double_free_guard(void)
{
    hx_mempool_t *mp = hx_mempool_create("test", 2, 32);
    assert(mp != NULL);

    void *a = hx_mempool_alloc(mp);
    assert(a != NULL);
    assert(hx_mempool_avail(mp) == 1);

    hx_mempool_free(mp, a);
    assert(hx_mempool_avail(mp) == 2);

    /* Double free — pool is full, should be silently ignored */
    hx_mempool_free(mp, a);
    assert(hx_mempool_avail(mp) == 2);

    hx_mempool_destroy(mp);
    printf("  PASS: test_double_free_guard\n");
}

static void test_null_safety(void)
{
    assert(hx_mempool_avail(NULL) == 0);
    assert(hx_mempool_alloc(NULL) == NULL);
    hx_mempool_free(NULL, NULL); /* should not crash */
    hx_mempool_destroy(NULL);    /* should not crash */
    printf("  PASS: test_null_safety\n");
}

static void test_write_read_data(void)
{
    hx_mempool_t *mp = hx_mempool_create("test", 4, 256);
    assert(mp != NULL);

    char *buf = hx_mempool_alloc(mp);
    assert(buf != NULL);

    /* Write data and verify it persists */
    memcpy(buf, "hello mempool", 14);
    assert(strcmp(buf, "hello mempool") == 0);

    hx_mempool_free(mp, buf);
    hx_mempool_destroy(mp);
    printf("  PASS: test_write_read_data\n");
}

int main(void)
{
    printf("test_mempool:\n");
    test_create_destroy();
    test_create_invalid();
    test_alloc_free();
    test_exhaust_pool();
    test_double_free_guard();
    test_null_safety();
    test_write_read_data();
    printf("All mempool tests passed.\n");
    return 0;
}
