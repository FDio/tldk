# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2016-2022 Intel Corporation

# This file is heavily based on the DPDK implementation

apps = []

test_apps = [
        'test-dring',
        'test-memtank',
        'test-timer',
]

if get_option('tests')
    apps += test_apps
endif

default_cflags = ['-march=native', '-mno-avx512f']
if cc.has_argument('-Wno-format-truncation')
    default_cflags += '-Wno-format-truncation'
endif

default_ldflags = tldk_extra_ldflags
if get_option('default_library') == 'static'
    default_ldflags += ['-Wl,--export-dynamic']
endif

foreach app:apps
    name = app
    build = true
    sources = []
    includes = []
    cflags = default_cflags
    ldflags = default_ldflags

    # use "deps" for internal TLDK dependencies, and "ext_deps" for
    # external package/library requirements
    ext_deps = []
    deps = []

    subdir(name)

    if build
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
    endif

    if not build
        message('Skipping app "' + name + '"')
        continue
    endif

    link_libs = []
    if get_option('default_library') == 'static'
        link_libs = tldk_static_libraries
    endif

    executable('tldk-' + name,
            sources,
            c_args: cflags,
            cpp_args: cflags,
            link_with: link_libs,
            link_args: ldflags,
            dependencies: ext_deps + dep_objs,
            include_directories: includes,
            install_rpath: get_option('prefix'),
            install: true)
endforeach

# special case for the unit tests
subdir('test')
