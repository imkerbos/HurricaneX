#include "hurricane/tls.h"
#include <stdlib.h>

/*
 * TLS engine skeleton.
 *
 * TODO: Integrate OpenSSL for actual TLS handshake and record-layer
 * processing. For now, provides the interface with stub implementations.
 */

struct hx_tls_ctx {
    hx_tls_version_t version;
    /* TODO: SSL_CTX pointer when OpenSSL is integrated */
};

struct hx_tls_session {
    hx_tls_ctx_t  *ctx;
    hx_tcp_conn_t *conn;
    bool           handshake_done;
    /* TODO: SSL pointer when OpenSSL is integrated */
};

hx_tls_ctx_t *hx_tls_ctx_create(hx_tls_version_t version)
{
    hx_tls_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->version = version;

    /* TODO: Initialize OpenSSL SSL_CTX */

    return ctx;
}

void hx_tls_ctx_destroy(hx_tls_ctx_t *ctx)
{
    if (!ctx)
        return;
    /* TODO: Free OpenSSL SSL_CTX */
    free(ctx);
}

hx_tls_session_t *hx_tls_session_create(hx_tls_ctx_t *ctx,
                                          hx_tcp_conn_t *conn)
{
    if (!ctx || !conn)
        return NULL;

    hx_tls_session_t *sess = calloc(1, sizeof(*sess));
    if (!sess)
        return NULL;

    sess->ctx = ctx;
    sess->conn = conn;
    sess->handshake_done = false;

    /* TODO: Create OpenSSL SSL object, attach BIO */

    return sess;
}

void hx_tls_session_destroy(hx_tls_session_t *sess)
{
    if (!sess)
        return;
    /* TODO: Free OpenSSL SSL object */
    free(sess);
}

hx_result_t hx_tls_handshake(hx_tls_session_t *sess)
{
    if (!sess)
        return HX_ERR_INVAL;

    /* TODO: Drive OpenSSL handshake via custom BIO that uses hx_tcp */

    sess->handshake_done = true;
    return HX_OK;
}

hx_result_t hx_tls_send(hx_tls_session_t *sess,
                          const hx_u8 *data, hx_u32 len)
{
    if (!sess || !data)
        return HX_ERR_INVAL;
    if (!sess->handshake_done)
        return HX_ERR_TLS;

    /* TODO: SSL_write -> custom BIO -> hx_tcp_send */
    (void)len;

    return HX_OK;
}

hx_result_t hx_tls_recv(hx_tls_session_t *sess,
                          hx_u8 *buf, hx_u32 buf_size, hx_u32 *out_len)
{
    if (!sess || !buf || !out_len)
        return HX_ERR_INVAL;
    if (!sess->handshake_done)
        return HX_ERR_TLS;

    /* TODO: SSL_read -> custom BIO -> hx_tcp_input */
    (void)buf_size;
    *out_len = 0;

    return HX_OK;
}
