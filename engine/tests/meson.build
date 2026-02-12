test('test_http',
  executable('test_http', 'test_http.c',
    dependencies : libhurricane_dep,
  ),
)

test('test_tcp',
  executable('test_tcp', 'test_tcp.c',
    dependencies : libhurricane_dep,
  ),
)

test('test_net',
  executable('test_net', 'test_net.c',
    dependencies : libhurricane_dep,
  ),
)

test('test_log',
  executable('test_log', 'test_log.c',
    dependencies : libhurricane_dep,
  ),
)

test('test_mempool',
  executable('test_mempool', 'test_mempool.c',
    dependencies : libhurricane_dep,
  ),
)

test('test_pktio',
  executable('test_pktio', 'test_pktio.c',
    dependencies : libhurricane_dep,
  ),
)

test('test_tls',
  executable('test_tls', 'test_tls.c',
    dependencies : libhurricane_dep,
  ),
)

test('test_socket',
  executable('test_socket', 'test_socket.c',
    dependencies : libhurricane_dep,
  ),
)

test('test_mbuf_cache',
  executable('test_mbuf_cache', 'test_mbuf_cache.c',
    dependencies : libhurricane_dep,
  ),
)

test('test_work_space',
  executable('test_work_space', 'test_work_space.c',
    dependencies : libhurricane_dep,
  ),
)

# L4 TCP benchmark — AF_XDP handshake test (needs root + NIC)
executable('bench_l4', 'bench_l4.c',
  dependencies : libhurricane_dep,
)

# L7 HTTP benchmark — AF_XDP HTTP request test (needs root + NIC)
executable('bench_http', 'bench_http.c',
  dependencies : libhurricane_dep,
)
