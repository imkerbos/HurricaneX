engine_inc = include_directories('include')

openssl_dep = dependency('openssl', required : true)
dpdk_dep = dependency('libdpdk', required : false)

engine_sources = files(
  'src/common.c',
  'src/config.c',
  'src/conn_table.c',
  'src/engine.c',
  'src/log.c',
  'src/mempool.c',
  'src/net.c',
  'src/pktio.c',
  'src/pktio_mock.c',
  'src/tcp.c',
  'src/http.c',
  'src/tls.c',
)

engine_deps = [openssl_dep]

if dpdk_dep.found()
  engine_sources += files('src/pktio_dpdk.c', 'src/dpdk_init.c')
  engine_deps += dpdk_dep
  add_project_arguments('-DHX_USE_DPDK', language : 'c')
  message('DPDK found — building with DPDK pktio backend')
else
  message('DPDK not found — building with mock pktio only')
endif

libhurricane = static_library('hurricane',
  engine_sources,
  include_directories : engine_inc,
  dependencies : engine_deps,
)

libhurricane_dep = declare_dependency(
  include_directories : engine_inc,
  link_with : libhurricane,
  dependencies : engine_deps,
)

subdir('tests')
