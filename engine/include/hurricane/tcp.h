#ifndef HURRICANE_TCP_H
#define HURRICANE_TCP_H

#include "common.h"
#include "pktio.h"

/*
 * Custom TCP state machine for high-performance connection simulation.
 *
 * Does NOT use the kernel TCP stack — implements TCP directly on top of
 * raw packet I/O for maximum throughput. Manages SYN/SYN-ACK/ACK handshake,
 * data transfer, and FIN teardown.
 */

/* TCP connection states */
typedef enum {
    HX_TCP_CLOSED = 0,
    HX_TCP_SYN_SENT,
    HX_TCP_ESTABLISHED,
    HX_TCP_FIN_WAIT_1,
    HX_TCP_FIN_WAIT_2,
    HX_TCP_TIME_WAIT,
    HX_TCP_CLOSE_WAIT,
    HX_TCP_LAST_ACK,
} hx_tcp_state_t;

/* TCP connection control block */
typedef struct hx_tcp_conn {
    hx_tcp_state_t state;

    /* Local endpoint */
    hx_u32  src_ip;
    hx_u16  src_port;

    /* Remote endpoint */
    hx_u32  dst_ip;
    hx_u16  dst_port;

    /* Sequence tracking */
    hx_u32  snd_nxt;    /* next send sequence number */
    hx_u32  snd_una;    /* oldest unacknowledged */
    hx_u32  rcv_nxt;    /* next expected receive seq */

    /* Window */
    hx_u16  snd_wnd;
    hx_u16  rcv_wnd;

    /* Packet I/O reference */
    hx_pktio_t *pktio;
} hx_tcp_conn_t;

/* Initialize a TCP connection (sets state to CLOSED) */
hx_result_t hx_tcp_init(hx_tcp_conn_t *conn, hx_pktio_t *pktio);

/* Initiate active open (send SYN) */
hx_result_t hx_tcp_connect(hx_tcp_conn_t *conn,
                            hx_u32 dst_ip, hx_u16 dst_port);

/* Send data on an established connection */
hx_result_t hx_tcp_send(hx_tcp_conn_t *conn,
                         const hx_u8 *data, hx_u32 len);

/* Process an incoming packet for this connection */
hx_result_t hx_tcp_input(hx_tcp_conn_t *conn, const hx_pkt_t *pkt);

/* Initiate graceful close (send FIN) */
hx_result_t hx_tcp_close(hx_tcp_conn_t *conn);

/* Get human-readable state name */
const char *hx_tcp_state_str(hx_tcp_state_t state);

#endif /* HURRICANE_TCP_H */
