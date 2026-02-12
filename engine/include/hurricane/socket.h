#ifndef HURRICANE_SOCKET_H
#define HURRICANE_SOCKET_H

#include "common.h"

/*
 * High-performance socket structure — 64 bytes, fits in 1 CPU cache line.
 *
 * Inspired by dperf: pre-computed checksums, minimal fields, O(1) lookup.
 * No per-socket MAC addresses or receive buffers — those live in
 * work_space (shared) and mbuf (zero-copy) respectively.
 */

/* Socket states (4 bits, max 15) */
enum hx_sk_state {
    HX_SK_CLOSED       = 0,
    HX_SK_SYN_SENT     = 1,
    HX_SK_SYN_RECEIVED = 2,
    HX_SK_ESTABLISHED  = 3,
    HX_SK_FIN_WAIT_1   = 4,
    HX_SK_FIN_WAIT_2   = 5,
    HX_SK_TIME_WAIT    = 6,
    HX_SK_CLOSE_WAIT   = 7,
    HX_SK_LAST_ACK     = 8,
};

/* Application-layer state */
enum hx_app_state {
    HX_APP_IDLE      = 0,   /* no app layer / done */
    HX_APP_HTTP_SEND = 1,   /* need to send HTTP request */
    HX_APP_HTTP_RECV = 2,   /* waiting for HTTP response */
};

/*
 * 64-byte socket — 1 cache line.
 *
 * Layout:
 *   [0..15]  TCP sequence tracking + state
 *   [16..23] Timer (TSC-based)
 *   [24..31] Pre-computed checksums
 *   [32..47] 4-tuple (network byte order)
 *   [48..63] App state + counters
 */
struct hx_socket {
    /* --- TCP state (16 bytes) --- */
    hx_u32  rcv_nxt;           /* next expected receive seq */
    hx_u32  snd_nxt;           /* next send seq */
    hx_u32  snd_una;           /* oldest unacked seq */
    hx_u8   flags;             /* last sent TCP flags */
    hx_u8   state;             /* hx_sk_state (4 bits used) */
    hx_u8   retrans;           /* retransmit count */
    hx_u8   app_state;         /* hx_app_state */

    /* --- Timer (8 bytes) --- */
    hx_u64  timer_tsc;         /* retransmit/timeout expiration (TSC) */

    /* --- Pre-computed partial checksums (8 bytes) --- */
    hx_u16  csum_tcp;          /* ACK/FIN template checksum */
    hx_u16  csum_tcp_opt;      /* SYN template checksum */
    hx_u16  csum_tcp_data;     /* DATA template checksum */
    hx_u16  csum_ip;           /* IP header checksum */

    /* --- 4-tuple, network byte order (16 bytes) --- */
    hx_u32  laddr;             /* local IP */
    hx_u32  faddr;             /* foreign IP */
    hx_u16  lport;             /* local port */
    hx_u16  fport;             /* foreign port */
    hx_u16  pad0;
    hx_u16  http_reqs;         /* keepalive request counter */

    /* --- App + padding (8 bytes) --- */
    hx_u8   pad1[8];
} __attribute__((aligned(64)));

_Static_assert(sizeof(struct hx_socket) == 64, "hx_socket must be 64 bytes");

/* State name for logging */
const char *hx_sk_state_str(enum hx_sk_state state);

#endif /* HURRICANE_SOCKET_H */
