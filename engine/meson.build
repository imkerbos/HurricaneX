engine_inc = include_directories('include')

openssl_dep = dependency('openssl', required : true)

engine_sources = files(
  'src/common.c',
  'src/config.c',
  'src/log.c',
  'src/mempool.c',
  'src/net.c',
  'src/pktio.c',
  'src/pktio_mock.c',
  'src/socket.c',
  'src/mbuf_cache.c',
  'src/work_space.c',
  'src/tcp.c',
  'src/http.c',
  'src/tls.c',
)

engine_deps = [openssl_dep]

# AF_XDP backend — Linux only, requires libxdp + libbpf
if host_machine.system() == 'linux'
  libxdp_dep = dependency('libxdp', required : false)
  libbpf_dep = dependency('libbpf', required : false)

  if libxdp_dep.found() and libbpf_dep.found()
    engine_sources += files('src/pktio_xdp.c')
    engine_deps += [libxdp_dep, libbpf_dep]
    add_project_arguments('-DHX_USE_XDP', language : 'c')
    message('libxdp + libbpf found — building with AF_XDP pktio backend')
  else
    message('libxdp/libbpf not found — building with mock pktio only')
  endif
else
  message('Non-Linux host — building with mock pktio only')
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
