#include "hurricane/log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

static hx_log_level_t g_log_level = HX_LOG_LEVEL_INFO;

static const char *level_strings[] = {
    [HX_LOG_LEVEL_DEBUG] = "debug",
    [HX_LOG_LEVEL_INFO]  = "info",
    [HX_LOG_LEVEL_WARN]  = "warn",
    [HX_LOG_LEVEL_ERROR] = "error",
    [HX_LOG_LEVEL_FATAL] = "fatal",
};

hx_result_t hx_log_init(hx_log_level_t level)
{
    if (level > HX_LOG_LEVEL_FATAL)
        return HX_ERR_INVAL;

    g_log_level = level;

    return HX_OK;
}

const char *hx_log_level_str(hx_log_level_t level)
{
    if (level > HX_LOG_LEVEL_FATAL)
        return "unknown";
    return level_strings[level];
}

/* Format ISO 8601 timestamp with microsecond precision.
 * buf must be at least 32 bytes. Returns bytes written. */
static int format_timestamp(char *buf, size_t buf_size)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);

    int n = (int)strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%S", &tm);
    n += snprintf(buf + n, buf_size - (size_t)n, ".%06ldZ", ts.tv_nsec / 1000);
    return n;
}

/* Escape a string for JSON output.
 * Handles \, ", and control characters (< 0x20).
 * Returns bytes written (not counting null terminator). */
static int json_escape(char *dst, size_t dst_size, const char *src, size_t src_len)
{
    size_t di = 0;

    for (size_t si = 0; si < src_len && di + 6 < dst_size; si++) {
        char c = src[si];
        switch (c) {
        case '"':  dst[di++] = '\\'; dst[di++] = '"';  break;
        case '\\': dst[di++] = '\\'; dst[di++] = '\\'; break;
        case '\n': dst[di++] = '\\'; dst[di++] = 'n';  break;
        case '\r': dst[di++] = '\\'; dst[di++] = 'r';  break;
        case '\t': dst[di++] = '\\'; dst[di++] = 't';  break;
        default:
            if ((unsigned char)c < 0x20) {
                di += (size_t)snprintf(dst + di, dst_size - di,
                                       "\\u%04x", (unsigned char)c);
            } else {
                dst[di++] = c;
            }
            break;
        }
    }

    dst[di] = '\0';
    return (int)di;
}

void hx_log_write(hx_log_level_t level, const char *component,
                  const char *fmt, ...)
{
    if (level < g_log_level)
        return;

    /* Format the user message on stack */
    char msg_buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, ap);
    va_end(ap);

    /* Escape message for JSON */
    char escaped_msg[768];
    json_escape(escaped_msg, sizeof(escaped_msg), msg_buf, strlen(msg_buf));

    /* Format timestamp */
    char ts_buf[32];
    format_timestamp(ts_buf, sizeof(ts_buf));

    /* Build final JSON line */
    char line[1024];
    int n = snprintf(line, sizeof(line),
        "{\"ts\":\"%s\",\"level\":\"%s\",\"component\":\"%s\",\"msg\":\"%s\"}\n",
        ts_buf,
        level_strings[level],
        component ? component : "unknown",
        escaped_msg);

    if (n < 0 || (size_t)n >= sizeof(line))
        return; /* truncated, drop silently */

    fputs(line, stderr);
}
