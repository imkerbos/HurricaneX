#include "hurricane/tls.h"
#include "hurricane/log.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdlib.h>
#include <string.h>

/*
 * TLS engine backed by OpenSSL.
 *
 * Uses a custom BIO pair to bridge OpenSSL's I/O with our TCP layer:
 *
 *   SSL_write(data) -> internal_bio -> [encrypted bytes] -> read from
 *   network_bio -> hx_tcp_send()
 *
 *   hx_tcp_input(pkt) -> write to network_bio -> [encrypted bytes] ->
 *   internal_bio -> SSL_read(data)
 *
 * This avoids any socket dependency — OpenSSL operates purely on memory
 * buffers, and we shuttle bytes between the BIO pair and our custom TCP.
 */

/* --- Internal buffer for BIO <-> TCP bridging -------------------------- */

#define HX_TLS_BUF_SIZE 32768

struct hx_tls_ctx {
    hx_tls_version_t version;
    SSL_CTX         *ssl_ctx;
};

struct hx_tls_session {
    hx_tls_ctx_t  *ctx;
    hx_tcp_conn_t *conn;
    SSL           *ssl;
    BIO           *internal_bio;  /* SSL reads/writes to this */
    BIO           *network_bio;   /* we read/write to this (the network side) */
    bool           handshake_done;
    hx_u8          net_buf[HX_TLS_BUF_SIZE]; /* scratch buffer for BIO<->TCP */
};

/* --- OpenSSL one-time init --------------------------------------------- */

static bool g_openssl_inited = false;

static void hx_tls_ensure_init(void)
{
    if (!g_openssl_inited) {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                         OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
        g_openssl_inited = true;
    }
}

/* --- Flush: push pending encrypted bytes from BIO to TCP --------------- */

static hx_result_t hx_tls_flush_to_tcp(hx_tls_session_t *sess)
{
    int pending;
    while ((pending = BIO_ctrl_pending(sess->network_bio)) > 0) {
        int to_read = pending;
        if (to_read > (int)sizeof(sess->net_buf))
            to_read = (int)sizeof(sess->net_buf);

        int n = BIO_read(sess->network_bio, sess->net_buf, to_read);
        if (n <= 0)
            break;

        hx_result_t rc = hx_tcp_send(sess->conn, sess->net_buf, (hx_u32)n);
        if (rc != HX_OK)
            return rc;
    }
    return HX_OK;
}

/* --- Public API -------------------------------------------------------- */

hx_tls_ctx_t *hx_tls_ctx_create(hx_tls_version_t version)
{
    hx_tls_ensure_init();

    hx_tls_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->version = version;

    /* Use TLS_client_method — we're always the client in traffic simulation */
    ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx->ssl_ctx) {
        free(ctx);
        return NULL;
    }

    /* Set min/max TLS version based on config */
    switch (version) {
    case HX_TLS_VERSION_12:
        SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx->ssl_ctx, TLS1_2_VERSION);
        break;
    case HX_TLS_VERSION_13:
        SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
        break;
    }

    /* For traffic simulation, we don't verify server certs by default */
    SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);

    /* Enable session caching for TLS resumption benchmarks */
    SSL_CTX_set_session_cache_mode(ctx->ssl_ctx, SSL_SESS_CACHE_CLIENT);

    return ctx;
}

void hx_tls_ctx_destroy(hx_tls_ctx_t *ctx)
{
    if (!ctx)
        return;
    if (ctx->ssl_ctx)
        SSL_CTX_free(ctx->ssl_ctx);
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

    /* Create SSL object */
    sess->ssl = SSL_new(ctx->ssl_ctx);
    if (!sess->ssl) {
        free(sess);
        return NULL;
    }

    /*
     * Create a BIO pair:
     * - internal_bio: attached to SSL, OpenSSL reads/writes here
     * - network_bio: we read/write here to shuttle bytes to/from TCP
     */
    if (!BIO_new_bio_pair(&sess->internal_bio, HX_TLS_BUF_SIZE,
                           &sess->network_bio, HX_TLS_BUF_SIZE)) {
        SSL_free(sess->ssl);
        free(sess);
        return NULL;
    }

    SSL_set_bio(sess->ssl, sess->internal_bio, sess->internal_bio);

    /* Set connect state — we're the client */
    SSL_set_connect_state(sess->ssl);

    return sess;
}

void hx_tls_session_destroy(hx_tls_session_t *sess)
{
    if (!sess)
        return;

    if (sess->ssl) {
        /*
         * SSL_free will free internal_bio (it was set via SSL_set_bio).
         * We must free network_bio ourselves.
         */
        SSL_free(sess->ssl);
    }
    if (sess->network_bio)
        BIO_free(sess->network_bio);

    free(sess);
}

hx_result_t hx_tls_handshake(hx_tls_session_t *sess)
{
    if (!sess)
        return HX_ERR_INVAL;

    if (sess->handshake_done)
        return HX_OK;

    int ret = SSL_do_handshake(sess->ssl);

    /* Flush any outgoing handshake data to TCP */
    hx_result_t flush_rc = hx_tls_flush_to_tcp(sess);
    if (flush_rc != HX_OK)
        return flush_rc;

    if (ret == 1) {
        sess->handshake_done = true;
        return HX_OK;
    }

    int err = SSL_get_error(sess->ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return HX_ERR_AGAIN; /* need more data from peer */
    }

    return HX_ERR_TLS;
}

hx_result_t hx_tls_send(hx_tls_session_t *sess,
                          const hx_u8 *data, hx_u32 len)
{
    if (!sess || !data)
        return HX_ERR_INVAL;
    if (!sess->handshake_done)
        return HX_ERR_TLS;

    int written = SSL_write(sess->ssl, data, (int)len);
    if (written <= 0) {
        int err = SSL_get_error(sess->ssl, written);
        if (err == SSL_ERROR_WANT_WRITE)
            return HX_ERR_AGAIN;
        return HX_ERR_TLS;
    }

    /* Flush encrypted data to TCP */
    return hx_tls_flush_to_tcp(sess);
}

hx_result_t hx_tls_recv(hx_tls_session_t *sess,
                          hx_u8 *buf, hx_u32 buf_size, hx_u32 *out_len)
{
    if (!sess || !buf || !out_len)
        return HX_ERR_INVAL;
    if (!sess->handshake_done)
        return HX_ERR_TLS;

    *out_len = 0;

    int n = SSL_read(sess->ssl, buf, (int)buf_size);
    if (n > 0) {
        *out_len = (hx_u32)n;
        return HX_OK;
    }

    int err = SSL_get_error(sess->ssl, n);
    if (err == SSL_ERROR_WANT_READ)
        return HX_ERR_AGAIN;
    if (err == SSL_ERROR_ZERO_RETURN)
        return HX_OK; /* clean shutdown, 0 bytes */

    return HX_ERR_TLS;
}

/*
 * Feed incoming TCP data into the TLS session's network BIO.
 * Call this when hx_tcp_input() delivers data that belongs to a TLS session.
 */
hx_result_t hx_tls_feed_data(hx_tls_session_t *sess,
                               const hx_u8 *data, hx_u32 len)
{
    if (!sess || !data)
        return HX_ERR_INVAL;

    int written = BIO_write(sess->network_bio, data, (int)len);
    if (written <= 0)
        return HX_ERR_NOMEM;
    if ((hx_u32)written != len)
        return HX_ERR_AGAIN; /* partial write, BIO buffer full */

    return HX_OK;
}
