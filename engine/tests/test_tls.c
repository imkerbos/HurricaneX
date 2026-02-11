#include "hurricane/tls.h"
#include "hurricane/mempool.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_ctx_create_destroy_tls12(void)
{
    hx_tls_ctx_t *ctx = hx_tls_ctx_create(HX_TLS_VERSION_12);
    assert(ctx != NULL);
    hx_tls_ctx_destroy(ctx);
    printf("  PASS: test_ctx_create_destroy_tls12\n");
}

static void test_ctx_create_destroy_tls13(void)
{
    hx_tls_ctx_t *ctx = hx_tls_ctx_create(HX_TLS_VERSION_13);
    assert(ctx != NULL);
    hx_tls_ctx_destroy(ctx);
    printf("  PASS: test_ctx_create_destroy_tls13\n");
}

static void test_ctx_destroy_null(void)
{
    hx_tls_ctx_destroy(NULL); /* should not crash */
    printf("  PASS: test_ctx_destroy_null\n");
}

static void test_session_create_destroy(void)
{
    hx_tls_ctx_t *ctx = hx_tls_ctx_create(HX_TLS_VERSION_13);
    assert(ctx != NULL);

    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;

    hx_tls_session_t *sess = hx_tls_session_create(ctx, &conn);
    assert(sess != NULL);

    hx_tls_session_destroy(sess);
    hx_tls_ctx_destroy(ctx);
    printf("  PASS: test_session_create_destroy\n");
}

static void test_session_create_null_args(void)
{
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);

    assert(hx_tls_session_create(NULL, &conn) == NULL);
    assert(hx_tls_session_create(NULL, NULL) == NULL);

    hx_tls_ctx_t *ctx = hx_tls_ctx_create(HX_TLS_VERSION_13);
    assert(hx_tls_session_create(ctx, NULL) == NULL);
    hx_tls_ctx_destroy(ctx);

    printf("  PASS: test_session_create_null_args\n");
}

static void test_session_destroy_null(void)
{
    hx_tls_session_destroy(NULL); /* should not crash */
    printf("  PASS: test_session_destroy_null\n");
}

static void test_handshake_needs_peer(void)
{
    hx_tls_ctx_t *ctx = hx_tls_ctx_create(HX_TLS_VERSION_13);
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;

    hx_tls_session_t *sess = hx_tls_session_create(ctx, &conn);
    assert(sess != NULL);

    /*
     * Handshake without a real peer should return HX_ERR_AGAIN
     * (SSL_do_handshake generates ClientHello, then wants to read
     * ServerHello — which won't arrive without a peer).
     *
     * The TCP conn has no pktio, so flush_to_tcp will fail on send.
     * This is expected — we're testing that the SSL machinery initializes.
     */
    hx_result_t rc = hx_tls_handshake(sess);
    /* Either AGAIN (wants peer data) or INVAL (no pktio to flush) is acceptable */
    assert(rc == HX_ERR_AGAIN || rc == HX_ERR_INVAL);

    hx_tls_session_destroy(sess);
    hx_tls_ctx_destroy(ctx);
    printf("  PASS: test_handshake_needs_peer\n");
}

static void test_send_before_handshake(void)
{
    hx_tls_ctx_t *ctx = hx_tls_ctx_create(HX_TLS_VERSION_13);
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;

    hx_tls_session_t *sess = hx_tls_session_create(ctx, &conn);
    assert(sess != NULL);

    hx_u8 data[] = "hello";
    assert(hx_tls_send(sess, data, sizeof(data)) == HX_ERR_TLS);

    hx_tls_session_destroy(sess);
    hx_tls_ctx_destroy(ctx);
    printf("  PASS: test_send_before_handshake\n");
}

static void test_recv_before_handshake(void)
{
    hx_tls_ctx_t *ctx = hx_tls_ctx_create(HX_TLS_VERSION_13);
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;

    hx_tls_session_t *sess = hx_tls_session_create(ctx, &conn);
    assert(sess != NULL);

    hx_u8 buf[256];
    hx_u32 out_len = 0;
    assert(hx_tls_recv(sess, buf, sizeof(buf), &out_len) == HX_ERR_TLS);

    hx_tls_session_destroy(sess);
    hx_tls_ctx_destroy(ctx);
    printf("  PASS: test_recv_before_handshake\n");
}

static void test_feed_data_null(void)
{
    assert(hx_tls_feed_data(NULL, NULL, 0) == HX_ERR_INVAL);

    hx_tls_ctx_t *ctx = hx_tls_ctx_create(HX_TLS_VERSION_13);
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;
    hx_tls_session_t *sess = hx_tls_session_create(ctx, &conn);

    assert(hx_tls_feed_data(sess, NULL, 0) == HX_ERR_INVAL);

    hx_tls_session_destroy(sess);
    hx_tls_ctx_destroy(ctx);
    printf("  PASS: test_feed_data_null\n");
}

static void test_feed_data_valid(void)
{
    hx_tls_ctx_t *ctx = hx_tls_ctx_create(HX_TLS_VERSION_13);
    hx_tcp_conn_t conn;
    hx_tcp_init(&conn, NULL);
    conn.state = HX_TCP_ESTABLISHED;
    hx_tls_session_t *sess = hx_tls_session_create(ctx, &conn);

    /* Feed some dummy data — it won't be valid TLS, but the BIO write should succeed */
    hx_u8 dummy[64];
    memset(dummy, 0xAB, sizeof(dummy));
    assert(hx_tls_feed_data(sess, dummy, sizeof(dummy)) == HX_OK);

    hx_tls_session_destroy(sess);
    hx_tls_ctx_destroy(ctx);
    printf("  PASS: test_feed_data_valid\n");
}

static void test_handshake_null(void)
{
    assert(hx_tls_handshake(NULL) == HX_ERR_INVAL);
    printf("  PASS: test_handshake_null\n");
}

static void test_send_null(void)
{
    assert(hx_tls_send(NULL, NULL, 0) == HX_ERR_INVAL);
    printf("  PASS: test_send_null\n");
}

static void test_recv_null(void)
{
    hx_u8 buf[16];
    hx_u32 out = 0;
    assert(hx_tls_recv(NULL, buf, sizeof(buf), &out) == HX_ERR_INVAL);
    printf("  PASS: test_recv_null\n");
}

int main(void)
{
    printf("test_tls:\n");
    test_ctx_create_destroy_tls12();
    test_ctx_create_destroy_tls13();
    test_ctx_destroy_null();
    test_session_create_destroy();
    test_session_create_null_args();
    test_session_destroy_null();
    test_handshake_needs_peer();
    test_send_before_handshake();
    test_recv_before_handshake();
    test_feed_data_null();
    test_feed_data_valid();
    test_handshake_null();
    test_send_null();
    test_recv_null();
    printf("All TLS tests passed.\n");
    return 0;
}
