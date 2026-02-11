#include "hurricane/tcp.h"
#include <string.h>

const char *hx_tcp_state_str(hx_tcp_state_t state)
{
    switch (state) {
    case HX_TCP_CLOSED:      return "CLOSED";
    case HX_TCP_SYN_SENT:    return "SYN_SENT";
    case HX_TCP_ESTABLISHED: return "ESTABLISHED";
    case HX_TCP_FIN_WAIT_1:  return "FIN_WAIT_1";
    case HX_TCP_FIN_WAIT_2:  return "FIN_WAIT_2";
    case HX_TCP_TIME_WAIT:   return "TIME_WAIT";
    case HX_TCP_CLOSE_WAIT:  return "CLOSE_WAIT";
    case HX_TCP_LAST_ACK:    return "LAST_ACK";
    default:                 return "UNKNOWN";
    }
}

hx_result_t hx_tcp_init(hx_tcp_conn_t *conn, hx_pktio_t *pktio)
{
    if (!conn)
        return HX_ERR_INVAL;

    memset(conn, 0, sizeof(*conn));
    conn->state = HX_TCP_CLOSED;
    conn->pktio = pktio;
    conn->rcv_wnd = 65535;
    conn->snd_wnd = 65535;

    return HX_OK;
}

hx_result_t hx_tcp_connect(hx_tcp_conn_t *conn,
                            hx_u32 dst_ip, hx_u16 dst_port)
{
    if (!conn)
        return HX_ERR_INVAL;
    if (conn->state != HX_TCP_CLOSED)
        return HX_ERR_INVAL;

    conn->dst_ip = dst_ip;
    conn->dst_port = dst_port;

    /* TODO: Build and send SYN packet via pktio */
    /* TODO: Generate initial sequence number */

    conn->state = HX_TCP_SYN_SENT;
    return HX_OK;
}

hx_result_t hx_tcp_send(hx_tcp_conn_t *conn,
                         const hx_u8 *data, hx_u32 len)
{
    if (!conn || !data)
        return HX_ERR_INVAL;
    if (conn->state != HX_TCP_ESTABLISHED)
        return HX_ERR_INVAL;

    /* TODO: Segment data, build TCP packets, send via pktio */
    (void)len;

    return HX_OK;
}

hx_result_t hx_tcp_input(hx_tcp_conn_t *conn, const hx_pkt_t *pkt)
{
    if (!conn || !pkt)
        return HX_ERR_INVAL;

    /* TODO: Parse TCP header from packet */
    /* TODO: State machine transitions based on flags:
     *   CLOSED + SYN-ACK -> ESTABLISHED (complete handshake)
     *   ESTABLISHED + FIN -> CLOSE_WAIT
     *   FIN_WAIT_1 + ACK -> FIN_WAIT_2
     *   FIN_WAIT_2 + FIN -> TIME_WAIT
     *   etc.
     */

    return HX_OK;
}

hx_result_t hx_tcp_close(hx_tcp_conn_t *conn)
{
    if (!conn)
        return HX_ERR_INVAL;
    if (conn->state != HX_TCP_ESTABLISHED)
        return HX_ERR_INVAL;

    /* TODO: Build and send FIN packet via pktio */

    conn->state = HX_TCP_FIN_WAIT_1;
    return HX_OK;
}
