# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2016-2022 Intel Corporation

if not get_option('tests')
    subdir_done()
endif

sources = files('main.cpp',
    'test_common.cpp',
    'test_tle_dring.cpp',
    'test_tle_ctx.cpp',
    'test_tle_udp_destroy.cpp',
    'test_tle_udp_event.cpp',
    'test_tle_udp_stream_gen.cpp',
    'test_tle_tcp_stream.cpp')

ext_deps += [gtest_dep, gmock_dep, libdpdk_dep]
deps += ['l4p']
ldflags += ['-lstdc++', '-lpthread']

# python pcap gen script
custom_target('scapy gen',
    input: 'test_scapy_gen.py',
    output: 'test_scapy_gen.py',
    command: ['cp', '@INPUT@', '@OUTPUT@'],
    install: false,
    build_by_default: true)

# actual unit test binary
dep_objs = []
foreach d:deps
    var_name = get_option('default_library') + '_tle_' + d
    if not is_variable(var_name)
        build = false
        message('Missing dependency "@0@" for app "@1@"'.format(d, name))
        break
    endif
    dep_objs += [get_variable(var_name)]
endforeach

link_libs = []
if get_option('default_library') == 'static'
    link_libs = tldk_static_libraries
endif

tldk_test = executable('tldk-test',
            sources,
            cpp_args: cflags,
            link_with: link_libs,
            link_args: ldflags,
            dependencies: ext_deps + dep_objs,
            include_directories: includes,
            install_rpath: get_option('prefix'),
            install: true)

test('unit tests', tldk_test,
            timeout: 300,
            is_parallel : false)
