engine_inc = include_directories('include')

engine_sources = files(
  'src/common.c',
  'src/config.c',
  'src/mempool.c',
  'src/pktio.c',
  'src/pktio_mock.c',
  'src/tcp.c',
  'src/http.c',
  'src/tls.c',
)

libhurricane = static_library('hurricane',
  engine_sources,
  include_directories : engine_inc,
)

libhurricane_dep = declare_dependency(
  include_directories : engine_inc,
  link_with : libhurricane,
)

subdir('tests')
