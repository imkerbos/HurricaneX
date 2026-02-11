#include "hurricane/http.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_method_str(void)
{
    assert(strcmp(hx_http_method_str(HX_HTTP_GET), "GET") == 0);
    assert(strcmp(hx_http_method_str(HX_HTTP_POST), "POST") == 0);
    assert(strcmp(hx_http_method_str(HX_HTTP_PUT), "PUT") == 0);
    assert(strcmp(hx_http_method_str(HX_HTTP_DELETE), "DELETE") == 0);
    assert(strcmp(hx_http_method_str(HX_HTTP_HEAD), "HEAD") == 0);
    printf("  PASS: test_method_str\n");
}

static void test_request_init(void)
{
    hx_http_request_t req;
    assert(hx_http_request_init(&req) == HX_OK);
    assert(req.method == HX_HTTP_GET);
    assert(strcmp(req.path, "/") == 0);
    assert(strlen(req.user_agent) > 0);
    printf("  PASS: test_request_init\n");
}

static void test_build_get_request(void)
{
    hx_http_request_t req;
    hx_http_request_init(&req);
    snprintf(req.host, sizeof(req.host), "example.com");

    hx_u8 buf[4096];
    hx_u32 len = 0;
    assert(hx_http_build_request(&req, buf, sizeof(buf), &len) == HX_OK);
    assert(len > 0);

    /* Verify it starts with "GET / HTTP/1.1\r\n" */
    assert(strncmp((char *)buf, "GET / HTTP/1.1\r\n", 16) == 0);

    /* Verify Host header */
    assert(strstr((char *)buf, "Host: example.com\r\n") != NULL);

    /* Verify ends with \r\n (empty line after headers) */
    assert(buf[len - 2] == '\r' && buf[len - 1] == '\n');

    printf("  PASS: test_build_get_request\n");
}

static void test_build_post_request(void)
{
    hx_http_request_t req;
    hx_http_request_init(&req);
    req.method = HX_HTTP_POST;
    snprintf(req.host, sizeof(req.host), "example.com");
    snprintf(req.path, sizeof(req.path), "/api/data");

    const char *body = "{\"key\":\"value\"}";
    req.body = (const hx_u8 *)body;
    req.body_len = (hx_u32)strlen(body);

    hx_u8 buf[4096];
    hx_u32 len = 0;
    assert(hx_http_build_request(&req, buf, sizeof(buf), &len) == HX_OK);

    assert(strncmp((char *)buf, "POST /api/data HTTP/1.1\r\n", 25) == 0);
    assert(strstr((char *)buf, "Content-Length: 15\r\n") != NULL);

    /* Body should be at the end */
    assert(strstr((char *)buf, "{\"key\":\"value\"}") != NULL);

    printf("  PASS: test_build_post_request\n");
}

static void test_parse_response(void)
{
    const char *raw =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "hello";

    hx_http_response_t resp;
    hx_result_t rc = hx_http_parse_response(
        (const hx_u8 *)raw, (hx_u32)strlen(raw), &resp);

    assert(rc == HX_OK);
    assert(resp.status_code == 200);
    assert(resp.header_len > 0);
    assert(resp.body_len == 5);
    assert(memcmp(resp.body_start, "hello", 5) == 0);
    assert(resp.content_length == 5);
    assert(resp.keep_alive == true);

    printf("  PASS: test_parse_response\n");
}

static void test_parse_connection_close(void)
{
    const char *raw =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 3\r\n"
        "Connection: close\r\n"
        "\r\n"
        "bye";

    hx_http_response_t resp;
    hx_result_t rc = hx_http_parse_response(
        (const hx_u8 *)raw, (hx_u32)strlen(raw), &resp);

    assert(rc == HX_OK);
    assert(resp.status_code == 200);
    assert(resp.content_length == 3);
    assert(resp.keep_alive == false);

    printf("  PASS: test_parse_connection_close\n");
}

static void test_parse_no_content_length(void)
{
    const char *raw =
        "HTTP/1.1 204 No Content\r\n"
        "Server: test\r\n"
        "\r\n";

    hx_http_response_t resp;
    hx_result_t rc = hx_http_parse_response(
        (const hx_u8 *)raw, (hx_u32)strlen(raw), &resp);

    assert(rc == HX_OK);
    assert(resp.status_code == 204);
    assert(resp.content_length == 0);
    assert(resp.keep_alive == true); /* HTTP/1.1 default */

    printf("  PASS: test_parse_no_content_length\n");
}

static void test_parse_large_content_length(void)
{
    const char *raw =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 1048576\r\n"
        "\r\n";

    hx_http_response_t resp;
    hx_result_t rc = hx_http_parse_response(
        (const hx_u8 *)raw, (hx_u32)strlen(raw), &resp);

    assert(rc == HX_OK);
    assert(resp.content_length == 1048576);

    printf("  PASS: test_parse_large_content_length\n");
}

static void test_parse_incomplete(void)
{
    const char *raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";

    hx_http_response_t resp;
    hx_result_t rc = hx_http_parse_response(
        (const hx_u8 *)raw, (hx_u32)strlen(raw), &resp);

    assert(rc == HX_ERR_AGAIN);
    printf("  PASS: test_parse_incomplete\n");
}

int main(void)
{
    printf("test_http:\n");
    test_method_str();
    test_request_init();
    test_build_get_request();
    test_build_post_request();
    test_parse_response();
    test_parse_connection_close();
    test_parse_no_content_length();
    test_parse_large_content_length();
    test_parse_incomplete();
    printf("All HTTP tests passed.\n");
    return 0;
}
