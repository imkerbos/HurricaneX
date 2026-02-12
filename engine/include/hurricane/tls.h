#ifndef HURRICANE_TLS_H
#define HURRICANE_TLS_H

#include "common.h"
#include "tcp.h"

/*
 * TLS engine for HTTPS traffic simulation.
 *
 * Manages TLS handshake and record-layer encryption/decryption
 * on top of the custom TCP connection. Uses OpenSSL for crypto.
 */

/* TLS version */
typedef enum {
    HX_TLS_VERSION_12 = 0,
    HX_TLS_VERSION_13,
} hx_tls_version_t;

/* TLS context (shared across connections, holds certs/keys) */
typedef struct hx_tls_ctx hx_tls_ctx_t;

/* TLS session (per-connection state) */
typedef struct hx_tls_session hx_tls_session_t;

/* Create a TLS context. `version` selects TLS 1.2 or 1.3. */
hx_tls_ctx_t *hx_tls_ctx_create(hx_tls_version_t version);

/* Destroy a TLS context */
void hx_tls_ctx_destroy(hx_tls_ctx_t *ctx);

/* Create a new TLS session bound to a TCP connection */
hx_tls_session_t *hx_tls_session_create(hx_tls_ctx_t *ctx,
                                          hx_tcp_conn_t *conn);

/* Destroy a TLS session */
void hx_tls_session_destroy(hx_tls_session_t *sess);

/* Perform TLS handshake. May need to be called multiple times.
 * Returns HX_OK when handshake is complete, HX_ERR_AGAIN if in progress. */
hx_result_t hx_tls_handshake(hx_tls_session_t *sess);

/* Encrypt and send data over TLS */
hx_result_t hx_tls_send(hx_tls_session_t *sess,
                          const hx_u8 *data, hx_u32 len);

/* Receive and decrypt data from TLS */
hx_result_t hx_tls_recv(hx_tls_session_t *sess,
                          hx_u8 *buf, hx_u32 buf_size, hx_u32 *out_len);

/*
 * Feed incoming TCP payload into the TLS session.
 * Call this when encrypted data arrives from the network (via hx_tcp_input).
 * After feeding, call hx_tls_handshake() or hx_tls_recv() to process it.
 */
hx_result_t hx_tls_feed_data(hx_tls_session_t *sess,
                               const hx_u8 *data, hx_u32 len);

#endif /* HURRICANE_TLS_H */
