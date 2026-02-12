project('hurricanex', 'c',
  version : '0.1.0',
  default_options : [
    'c_std=c11',
    'warning_level=2',
    'b_lundef=false',
  ],
)

# Sanitizers conflict with DPDK hugepage memory management.
# Disable with: meson setup build -Denable_sanitizers=false
if get_option('enable_sanitizers')
  add_project_arguments('-fsanitize=address,undefined', language : 'c')
  add_project_link_arguments('-fsanitize=address,undefined', language : 'c')
endif

add_project_arguments('-D_GNU_SOURCE', language : 'c')

subdir('engine')
