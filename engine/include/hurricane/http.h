#ifndef HURRICANE_HTTP_H
#define HURRICANE_HTTP_H

#include "common.h"

/*
 * HTTP/1.1 request construction and response parsing for traffic simulation.
 *
 * Builds raw HTTP request bytes suitable for direct injection into
 * TCP send buffers. Parses response status lines and headers.
 */

/* HTTP methods */
typedef enum {
    HX_HTTP_GET = 0,
    HX_HTTP_POST,
    HX_HTTP_PUT,
    HX_HTTP_DELETE,
    HX_HTTP_HEAD,
} hx_http_method_t;

/* HTTP request descriptor */
typedef struct hx_http_request {
    hx_http_method_t method;
    char             host[256];
    char             path[1024];
    char             user_agent[128];

    /* Optional body (for POST/PUT) */
    const hx_u8     *body;
    hx_u32           body_len;
} hx_http_request_t;

/* HTTP response (parsed from raw bytes) */
typedef struct hx_http_response {
    int              status_code;
    hx_u64           content_length;
    bool             keep_alive;

    /* Raw header region (points into receive buffer) */
    const hx_u8     *header_start;
    hx_u32           header_len;

    /* Body start offset within the receive buffer */
    const hx_u8     *body_start;
    hx_u32           body_len;
} hx_http_response_t;

/* Initialize an HTTP request with defaults */
hx_result_t hx_http_request_init(hx_http_request_t *req);

/*
 * Build a raw HTTP request into `buf`.
 * Returns HX_OK on success, sets *out_len to the number of bytes written.
 */
hx_result_t hx_http_build_request(const hx_http_request_t *req,
                                   hx_u8 *buf, hx_u32 buf_size,
                                   hx_u32 *out_len);

/*
 * Parse an HTTP response from raw bytes.
 * `data` / `len` should contain at least the complete header section.
 * Returns HX_OK if a complete header was found and parsed.
 * Returns HX_ERR_AGAIN if more data is needed.
 */
hx_result_t hx_http_parse_response(const hx_u8 *data, hx_u32 len,
                                    hx_http_response_t *resp);

/* Return the method string (e.g. "GET") */
const char *hx_http_method_str(hx_http_method_t method);

#endif /* HURRICANE_HTTP_H */
