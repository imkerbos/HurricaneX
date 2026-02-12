#include "hurricane/socket_table.h"
#include "hurricane/net.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* --- State string test ------------------------------------------------- */

static void test_sk_state_str(void)
{
    assert(strcmp(hx_sk_state_str(HX_SK_CLOSED), "CLOSED") == 0);
    assert(strcmp(hx_sk_state_str(HX_SK_SYN_SENT), "SYN_SENT") == 0);
    assert(strcmp(hx_sk_state_str(HX_SK_ESTABLISHED), "ESTABLISHED") == 0);
    assert(strcmp(hx_sk_state_str(HX_SK_FIN_WAIT_1), "FIN_WAIT_1") == 0);
    assert(strcmp(hx_sk_state_str((enum hx_sk_state)99), "UNKNOWN") == 0);
    printf("  PASS: test_sk_state_str\n");
}

/* --- Socket size test -------------------------------------------------- */

static void test_socket_size(void)
{
    assert(sizeof(struct hx_socket) == 64);
    printf("  PASS: test_socket_size (64 bytes)\n");
}

/* --- Table creation ---------------------------------------------------- */

static void test_table_create_basic(void)
{
    /* 10 connections: lport 10000..10009, single dst */
    struct hx_socket_table *st = hx_socket_table_create(
        0xC0A80001,          /* 192.168.0.1 */
        10000, 10009,        /* lport range */
        0x0A000001, 0x0A000001, /* single faddr 10.0.0.1 */
        80, 80);             /* single fport */

    assert(st != NULL);
    assert(st->total_sockets == 10);
    assert(st->lport_num == 10);
    assert(st->faddr_num == 1);
    assert(st->fport_num == 1);
    assert(hx_socket_table_count(st) == 10);

    hx_socket_table_destroy(st);
    printf("  PASS: test_table_create_basic\n");
}

static void test_table_create_invalid(void)
{
    /* lport_min > lport_max */
    assert(hx_socket_table_create(0, 100, 50, 1, 1, 80, 80) == NULL);
    /* faddr_min > faddr_max */
    assert(hx_socket_table_create(0, 100, 200, 10, 5, 80, 80) == NULL);
    printf("  PASS: test_table_create_invalid\n");
}

/* --- O(1) lookup ------------------------------------------------------- */

static void test_lookup(void)
{
    struct hx_socket_table *st = hx_socket_table_create(
        0xC0A80001,          /* 192.168.0.1 */
        10000, 10004,        /* 5 lports */
        0x0A000001, 0x0A000001, /* single faddr */
        80, 80);             /* single fport */
    assert(st != NULL);

    /* Lookup each socket by 4-tuple (network byte order) */
    hx_u32 laddr_n = hx_htonl(0xC0A80001);
    hx_u32 faddr_n = hx_htonl(0x0A000001);
    hx_u16 fport_n = hx_htons(80);

    for (hx_u16 p = 10000; p <= 10004; p++) {
        hx_u16 lport_n = hx_htons(p);
        struct hx_socket *sk = hx_socket_lookup(st, laddr_n, lport_n,
                                                 faddr_n, fport_n);
        assert(sk != NULL);
        assert(sk->laddr == laddr_n);
        assert(sk->faddr == faddr_n);
        assert(sk->lport == lport_n);
        assert(sk->fport == fport_n);
        assert(sk->state == HX_SK_CLOSED);
    }

    /* Out-of-range lookup should return NULL */
    hx_u16 bad_lport = hx_htons(9999);
    assert(hx_socket_lookup(st, laddr_n, bad_lport, faddr_n, fport_n) == NULL);

    hx_u16 bad_fport = hx_htons(81);
    assert(hx_socket_lookup(st, laddr_n, hx_htons(10000), faddr_n, bad_fport) == NULL);

    hx_u32 bad_faddr = hx_htonl(0x0A000002);
    assert(hx_socket_lookup(st, laddr_n, hx_htons(10000), bad_faddr, fport_n) == NULL);

    hx_socket_table_destroy(st);
    printf("  PASS: test_lookup\n");
}

/* --- Multi-target lookup (multiple faddr) ------------------------------ */

static void test_lookup_multi_faddr(void)
{
    /* 3 lports × 2 faddrs × 1 fport = 6 sockets */
    struct hx_socket_table *st = hx_socket_table_create(
        0xC0A80001,
        20000, 20002,           /* 3 lports */
        0x0A000001, 0x0A000002, /* 2 faddrs */
        443, 443);              /* 1 fport */
    assert(st != NULL);
    assert(st->total_sockets == 6);

    hx_u32 laddr_n = hx_htonl(0xC0A80001);
    hx_u16 fport_n = hx_htons(443);

    /* Verify each combination */
    for (hx_u16 lp = 20000; lp <= 20002; lp++) {
        for (hx_u32 fa = 0x0A000001; fa <= 0x0A000002; fa++) {
            struct hx_socket *sk = hx_socket_lookup(
                st, laddr_n, hx_htons(lp),
                hx_htonl(fa), fport_n);
            assert(sk != NULL);
            assert(sk->lport == hx_htons(lp));
            assert(sk->faddr == hx_htonl(fa));
        }
    }

    hx_socket_table_destroy(st);
    printf("  PASS: test_lookup_multi_faddr\n");
}

/* --- Sequential launch ------------------------------------------------- */

static void test_sequential_launch(void)
{
    struct hx_socket_table *st = hx_socket_table_create(
        0xC0A80001, 10000, 10004,
        0x0A000001, 0x0A000001,
        80, 80);
    assert(st != NULL);

    /* Launch all 5 sockets sequentially */
    for (int i = 0; i < 5; i++) {
        struct hx_socket *sk = hx_socket_table_next(st);
        assert(sk != NULL);
        assert(sk->state == HX_SK_CLOSED);
    }

    /* No more to launch */
    assert(hx_socket_table_next(st) == NULL);

    /* Reset and re-launch */
    hx_socket_table_reset_launch(st);
    struct hx_socket *sk = hx_socket_table_next(st);
    assert(sk != NULL);

    hx_socket_table_destroy(st);
    printf("  PASS: test_sequential_launch\n");
}

/* --- Pre-computed checksums -------------------------------------------- */

static void test_precomputed_checksums(void)
{
    struct hx_socket_table *st = hx_socket_table_create(
        0xC0A80001, 10000, 10000,
        0x0A000001, 0x0A000001,
        80, 80);
    assert(st != NULL);

    struct hx_socket *sk = &st->pool->sockets[0];

    /* Checksums should be non-zero (pseudo-header partial sum) */
    assert(sk->csum_tcp != 0);
    assert(sk->csum_tcp_opt != 0);

    hx_socket_table_destroy(st);
    printf("  PASS: test_precomputed_checksums\n");
}

/* --- main -------------------------------------------------------------- */

int main(void)
{
    printf("test_socket:\n");
    test_sk_state_str();
    test_socket_size();
    test_table_create_basic();
    test_table_create_invalid();
    test_lookup();
    test_lookup_multi_faddr();
    test_sequential_launch();
    test_precomputed_checksums();
    printf("All socket tests passed.\n");
    return 0;
}
