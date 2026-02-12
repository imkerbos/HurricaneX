#include "hurricane/common.h"

const char *hx_strerror(hx_result_t err)
{
    switch (err) {
    case HX_OK:             return "success";
    case HX_ERR_NOMEM:      return "out of memory";
    case HX_ERR_INVAL:      return "invalid argument";
    case HX_ERR_TIMEOUT:    return "operation timed out";
    case HX_ERR_CONNREFUSED: return "connection refused";
    case HX_ERR_CONNRESET:  return "connection reset";
    case HX_ERR_AGAIN:      return "try again";
    case HX_ERR_TLS:        return "TLS error";
    case HX_ERR_PROTO:      return "protocol error";
    case HX_ERR_INTERNAL:   return "internal error";
    case HX_ERR_DPDK:       return "DPDK error";
    default:                return "unknown error";
    }
}
