#include "hurricane/conn_table.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_create_destroy(void)
{
    hx_conn_table_t *ct = hx_conn_table_create(64);
    assert(ct != NULL);
    assert(hx_conn_table_count(ct) == 0);
    hx_conn_table_destroy(ct);

    /* Small capacity rounds up to 16 */
    ct = hx_conn_table_create(1);
    assert(ct != NULL);
    hx_conn_table_destroy(ct);

    /* NULL is safe */
    hx_conn_table_destroy(NULL);
    assert(hx_conn_table_count(NULL) == 0);

    printf("  PASS: test_create_destroy\n");
}

static void test_insert_lookup(void)
{
    hx_conn_table_t *ct = hx_conn_table_create(64);
    hx_u8 smac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    hx_u8 dmac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    hx_tcp_conn_t *c = hx_conn_table_insert(ct,
        0x0A000001, 12345, 0x0A000002, 80,
        NULL, smac, dmac);
    assert(c != NULL);
    assert(c->src_ip == 0x0A000001);
    assert(c->src_port == 12345);
    assert(c->dst_ip == 0x0A000002);
    assert(c->dst_port == 80);
    assert(c->state == HX_TCP_CLOSED);
    assert(memcmp(c->src_mac, smac, 6) == 0);
    assert(memcmp(c->dst_mac, dmac, 6) == 0);
    assert(hx_conn_table_count(ct) == 1);

    /* Lookup should find it */
    hx_tcp_conn_t *found = hx_conn_table_lookup(ct,
        0x0A000001, 12345, 0x0A000002, 80);
    assert(found == c);

    /* Lookup with wrong tuple should return NULL */
    assert(hx_conn_table_lookup(ct, 0x0A000001, 12345, 0x0A000002, 81) == NULL);
    assert(hx_conn_table_lookup(ct, 0x0A000001, 12346, 0x0A000002, 80) == NULL);

    /* Duplicate insert should fail */
    assert(hx_conn_table_insert(ct,
        0x0A000001, 12345, 0x0A000002, 80,
        NULL, smac, dmac) == NULL);

    hx_conn_table_destroy(ct);
    printf("  PASS: test_insert_lookup\n");
}

static void test_remove(void)
{
    hx_conn_table_t *ct = hx_conn_table_create(64);

    hx_conn_table_insert(ct, 0x0A000001, 1000, 0x0A000002, 80,
                          NULL, NULL, NULL);
    hx_conn_table_insert(ct, 0x0A000001, 1001, 0x0A000002, 80,
                          NULL, NULL, NULL);
    assert(hx_conn_table_count(ct) == 2);

    /* Remove first */
    assert(hx_conn_table_remove(ct, 0x0A000001, 1000, 0x0A000002, 80) == HX_OK);
    assert(hx_conn_table_count(ct) == 1);
    assert(hx_conn_table_lookup(ct, 0x0A000001, 1000, 0x0A000002, 80) == NULL);

    /* Second should still be there */
    assert(hx_conn_table_lookup(ct, 0x0A000001, 1001, 0x0A000002, 80) != NULL);

    /* Remove non-existent */
    assert(hx_conn_table_remove(ct, 0x0A000001, 9999, 0x0A000002, 80) == HX_ERR_INVAL);

    /* Remove second */
    assert(hx_conn_table_remove(ct, 0x0A000001, 1001, 0x0A000002, 80) == HX_OK);
    assert(hx_conn_table_count(ct) == 0);

    hx_conn_table_destroy(ct);
    printf("  PASS: test_remove\n");
}

static void test_many_connections(void)
{
    hx_conn_table_t *ct = hx_conn_table_create(256);

    /* Insert 180 connections (under 75% of 256) */
    int inserted = 0;
    for (hx_u16 port = 10000; port < 10200; port++) {
        hx_tcp_conn_t *c = hx_conn_table_insert(ct,
            0x0A000001, port, 0x0A000002, 80,
            NULL, NULL, NULL);
        if (c)
            inserted++;
    }
    /* Should get at least 192 (75% of 256) minus some */
    assert(inserted >= 190);
    assert(hx_conn_table_count(ct) == (hx_u32)inserted);

    /* Lookup all inserted */
    for (hx_u16 port = 10000; port < 10000 + (hx_u16)inserted; port++) {
        hx_tcp_conn_t *c = hx_conn_table_lookup(ct,
            0x0A000001, port, 0x0A000002, 80);
        assert(c != NULL);
        assert(c->src_port == port);
    }

    /* Remove half */
    for (hx_u16 port = 10000; port < 10000 + (hx_u16)(inserted / 2); port++) {
        assert(hx_conn_table_remove(ct,
            0x0A000001, port, 0x0A000002, 80) == HX_OK);
    }

    /* Remaining half should still be findable */
    for (hx_u16 port = (hx_u16)(10000 + inserted / 2);
         port < 10000 + (hx_u16)inserted; port++) {
        assert(hx_conn_table_lookup(ct,
            0x0A000001, port, 0x0A000002, 80) != NULL);
    }

    hx_conn_table_destroy(ct);
    printf("  PASS: test_many_connections\n");
}

static void test_hash_distribution(void)
{
    /* Verify different tuples produce different hashes */
    hx_u32 h1 = hx_conn_hash(0x0A000001, 1000, 0x0A000002, 80);
    hx_u32 h2 = hx_conn_hash(0x0A000001, 1001, 0x0A000002, 80);
    hx_u32 h3 = hx_conn_hash(0x0A000002, 1000, 0x0A000001, 80);
    assert(h1 != h2);
    assert(h1 != h3);
    assert(h2 != h3);

    /* Same tuple should produce same hash */
    assert(hx_conn_hash(0x0A000001, 1000, 0x0A000002, 80) == h1);

    printf("  PASS: test_hash_distribution\n");
}

int main(void)
{
    printf("test_conn_table:\n");
    test_create_destroy();
    test_insert_lookup();
    test_remove();
    test_many_connections();
    test_hash_distribution();
    printf("All conn_table tests passed.\n");
    return 0;
}
