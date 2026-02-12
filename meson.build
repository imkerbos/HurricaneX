project('hurricanex', 'c',
  version : '0.1.0',
  default_options : [
    'c_std=c11',
    'warning_level=2',
    'b_sanitize=address,undefined',
    'b_lundef=false',
  ],
)

add_project_arguments('-D_GNU_SOURCE', language : 'c')

subdir('engine')
