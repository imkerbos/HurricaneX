#ifndef HURRICANE_COMMON_H
#define HURRICANE_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Error codes */
typedef enum {
    HX_OK = 0,
    HX_ERR_NOMEM = -1,
    HX_ERR_INVAL = -2,
    HX_ERR_TIMEOUT = -3,
    HX_ERR_CONNREFUSED = -4,
    HX_ERR_CONNRESET = -5,
    HX_ERR_AGAIN = -6,
    HX_ERR_TLS = -7,
    HX_ERR_PROTO = -8,
    HX_ERR_INTERNAL = -9,
    HX_ERR_DPDK = -10,
} hx_result_t;

/* Return human-readable error string */
const char *hx_strerror(hx_result_t err);

/* Basic type aliases */
typedef uint8_t  hx_u8;
typedef uint16_t hx_u16;
typedef uint32_t hx_u32;
typedef uint64_t hx_u64;

/* Maximum burst size for packet I/O */
#define HX_MAX_BURST 64

/* Maximum packet size */
#define HX_MAX_PKT_SIZE 1518

/* Ethernet header size */
#define HX_ETHER_HDR_LEN 14

/* IPv4 header size (no options) */
#define HX_IPV4_HDR_LEN 20

/* TCP header size (no options) */
#define HX_TCP_HDR_LEN 20

/* TCP flags */
#define HX_TCP_FLAG_FIN  0x01
#define HX_TCP_FLAG_SYN  0x02
#define HX_TCP_FLAG_RST  0x04
#define HX_TCP_FLAG_PSH  0x08
#define HX_TCP_FLAG_ACK  0x10
#define HX_TCP_FLAG_URG  0x20

/* TCP header (network byte order in wire format, host order in struct) */
typedef struct hx_tcp_hdr {
    hx_u16 src_port;
    hx_u16 dst_port;
    hx_u32 seq;
    hx_u32 ack;
    hx_u8  data_off;   /* upper 4 bits = header length in 32-bit words */
    hx_u8  flags;
    hx_u16 window;
    hx_u16 checksum;
    hx_u16 urgent;
} hx_tcp_hdr_t;

#endif /* HURRICANE_COMMON_H */
