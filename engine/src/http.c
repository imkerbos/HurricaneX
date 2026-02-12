#include "hurricane/http.h"
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/*
 * Find the start of a header value by name within the header region.
 * Case-insensitive match. Returns pointer to value (after ": ") or NULL.
 */
static const char *hx_http_find_header(const char *headers, const char *hdr_end,
                                        const char *name)
{
    size_t name_len = strlen(name);

    const char *line = headers;
    while (line < hdr_end) {
        /* Find end of this line */
        const char *eol = line;
        while (eol < hdr_end && *eol != '\r')
            eol++;

        /* Check if line starts with "Name:" (case-insensitive) */
        if ((size_t)(eol - line) > name_len + 1 &&
            strncasecmp(line, name, name_len) == 0 &&
            line[name_len] == ':') {
            const char *val = line + name_len + 1;
            while (val < eol && *val == ' ')
                val++;
            return val;
        }

        /* Skip \r\n to next line */
        line = eol;
        if (line + 1 < hdr_end && line[0] == '\r' && line[1] == '\n')
            line += 2;
        else
            break;
    }
    return NULL;
}

const char *hx_http_method_str(hx_http_method_t method)
{
    switch (method) {
    case HX_HTTP_GET:    return "GET";
    case HX_HTTP_POST:   return "POST";
    case HX_HTTP_PUT:    return "PUT";
    case HX_HTTP_DELETE: return "DELETE";
    case HX_HTTP_HEAD:   return "HEAD";
    default:             return "GET";
    }
}

hx_result_t hx_http_request_init(hx_http_request_t *req)
{
    if (!req)
        return HX_ERR_INVAL;

    memset(req, 0, sizeof(*req));
    req->method = HX_HTTP_GET;
    snprintf(req->path, sizeof(req->path), "/");
    snprintf(req->user_agent, sizeof(req->user_agent), "HurricaneX/1.0");

    return HX_OK;
}

hx_result_t hx_http_build_request(const hx_http_request_t *req,
                                   hx_u8 *buf, hx_u32 buf_size,
                                   hx_u32 *out_len)
{
    if (!req || !buf || !out_len)
        return HX_ERR_INVAL;

    int written = snprintf((char *)buf, buf_size,
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n",
        hx_http_method_str(req->method),
        req->path,
        req->host,
        req->user_agent);

    if (written < 0 || (hx_u32)written >= buf_size)
        return HX_ERR_NOMEM;

    /* Add Content-Length for methods with body */
    if (req->body && req->body_len > 0) {
        int cl_written = snprintf((char *)buf + written,
            buf_size - written,
            "Content-Length: %u\r\n",
            req->body_len);
        if (cl_written < 0 || (hx_u32)(written + cl_written) >= buf_size)
            return HX_ERR_NOMEM;
        written += cl_written;
    }

    /* End of headers */
    if ((hx_u32)(written + 2) >= buf_size)
        return HX_ERR_NOMEM;
    buf[written++] = '\r';
    buf[written++] = '\n';

    /* Append body if present */
    if (req->body && req->body_len > 0) {
        if ((hx_u32)(written + req->body_len) > buf_size)
            return HX_ERR_NOMEM;
        memcpy(buf + written, req->body, req->body_len);
        written += req->body_len;
    }

    *out_len = (hx_u32)written;
    return HX_OK;
}

hx_result_t hx_http_parse_response(const hx_u8 *data, hx_u32 len,
                                    hx_http_response_t *resp)
{
    if (!data || !resp)
        return HX_ERR_INVAL;

    memset(resp, 0, sizeof(*resp));

    /* Find end of headers (\r\n\r\n) */
    const char *hdr_end = NULL;
    for (hx_u32 i = 0; i + 3 < len; i++) {
        if (data[i] == '\r' && data[i+1] == '\n' &&
            data[i+2] == '\r' && data[i+3] == '\n') {
            hdr_end = (const char *)&data[i];
            break;
        }
    }

    if (!hdr_end)
        return HX_ERR_AGAIN; /* incomplete headers */

    /* Parse status line: "HTTP/1.1 200 OK\r\n" */
    if (len < 12)
        return HX_ERR_PROTO;

    int status = 0;
    if (sscanf((const char *)data, "HTTP/1.%*d %d", &status) != 1)
        return HX_ERR_PROTO;

    resp->status_code = status;
    resp->header_start = data;
    resp->header_len = (hx_u32)(hdr_end - (const char *)data + 4);
    resp->body_start = data + resp->header_len;
    resp->body_len = len - resp->header_len;

    /* Parse Content-Length header */
    resp->content_length = 0;
    const char *cl_val = hx_http_find_header((const char *)data, hdr_end,
                                              "Content-Length");
    if (cl_val) {
        hx_u64 v = 0;
        if (sscanf(cl_val, "%" SCNu64, &v) == 1)
            resp->content_length = v;
    }

    /* Parse Connection header — default to keep-alive for HTTP/1.1 */
    resp->keep_alive = true;
    const char *conn_val = hx_http_find_header((const char *)data, hdr_end,
                                                "Connection");
    if (conn_val && strncasecmp(conn_val, "close", 5) == 0)
        resp->keep_alive = false;

    return HX_OK;
}
