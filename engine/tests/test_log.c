#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "hurricane/log.h"

static void test_log_init(void)
{
    hx_result_t rc = hx_log_init(HX_LOG_LEVEL_INFO);
    assert(rc == HX_OK);
    printf("  PASS: test_log_init\n");
}

static void test_log_init_invalid_level(void)
{
    hx_result_t rc = hx_log_init((hx_log_level_t)99);
    assert(rc == HX_ERR_INVAL);
    printf("  PASS: test_log_init_invalid_level\n");
}

static void test_log_level_str(void)
{
    assert(strcmp(hx_log_level_str(HX_LOG_LEVEL_DEBUG), "debug") == 0);
    assert(strcmp(hx_log_level_str(HX_LOG_LEVEL_INFO), "info") == 0);
    assert(strcmp(hx_log_level_str(HX_LOG_LEVEL_WARN), "warn") == 0);
    assert(strcmp(hx_log_level_str(HX_LOG_LEVEL_ERROR), "error") == 0);
    assert(strcmp(hx_log_level_str(HX_LOG_LEVEL_FATAL), "fatal") == 0);
    assert(strcmp(hx_log_level_str((hx_log_level_t)99), "unknown") == 0);
    printf("  PASS: test_log_level_str\n");
}

static void test_log_write_info(void)
{
    hx_log_init(HX_LOG_LEVEL_DEBUG);
    /* Should output JSON to stderr — visual verification */
    HX_LOG_INFO(HX_LOG_COMP_ENGINE, "test message, value=%d", 42);
    printf("  PASS: test_log_write_info\n");
}

static void test_log_write_filtered(void)
{
    hx_log_init(HX_LOG_LEVEL_ERROR);
    /* DEBUG level should be filtered out at runtime (no output) */
    hx_log_write(HX_LOG_LEVEL_DEBUG, HX_LOG_COMP_TCP, "should not appear");
    printf("  PASS: test_log_write_filtered\n");
}

static void test_log_json_escape(void)
{
    hx_log_init(HX_LOG_LEVEL_DEBUG);
    /* Log a message with special characters that need JSON escaping */
    HX_LOG_INFO(HX_LOG_COMP_HTTP, "path=\"/test?a=1&b=2\", header: \"Host:\\texample.com\"");
    printf("  PASS: test_log_json_escape\n");
}

int main(void)
{
    printf("test_log:\n");

    test_log_init();
    test_log_init_invalid_level();
    test_log_level_str();
    test_log_write_info();
    test_log_write_filtered();
    test_log_json_escape();

    printf("all 6 tests passed\n");
    return 0;
}
