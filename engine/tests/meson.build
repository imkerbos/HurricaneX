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

# DPDK smoke test — build only, not in auto-test (needs root + hugepages + NIC)
executable('smoke_dpdk', 'smoke_dpdk.c',
  dependencies : libhurricane_dep,
)
