# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2016-2022 Intel Corporation

# This file is heavily based on the DPDK implementation

# process all libraries equally, as far as possible
# "core" libs first, then others alphabetically as far as possible
libraries = [
        'dring',
        'memtank',
        'misc',
        'timer',
        'l4p',
]

default_cflags = ['-march=native', '-mno-avx512f']
if cc.has_argument('-Wno-format-truncation')
    default_cflags += '-Wno-format-truncation'
endif

foreach l:libraries
    build = true
    name = l
    sources = []
    headers = []
    includes = []
    cflags = default_cflags

    # use "deps" for internal TLDK dependencies, and "ext_deps" for
    # external package/library requirements
    ext_deps = [libdpdk_dep]
    deps = []

    subdir(l)

    if name != l
        warning('Library name, "@0@", and directory name, "@1@", do not match'.format(name, l))
    endif

    shared_deps = ext_deps
    static_deps = ext_deps
    foreach d:deps
        if not build
            break
        endif
        if not is_variable('shared_tle_' + d)
            build = false
            message('Disabling @1@ [@2@]: missing internal dependency "@0@"'
                    .format(d, name, 'lib/' + l))
        else
            shared_deps += [get_variable('shared_tle_' + d)]
            static_deps += [get_variable('static_tle_' + d)]
        endif
    endforeach

    tldk_conf.set('TLE_LIB_' + name.to_upper(), 1)
    install_headers(headers)

    libname = 'tle_' + name
    includes += include_directories(l)

    # static lib
    static_lib = static_library(libname,
            sources,
            #objects: objs,
            c_args: cflags,
            dependencies: static_deps,
            include_directories: includes,
            install: true)
    static_dep = declare_dependency(
            include_directories: includes,
            dependencies: static_deps)

    # shared lib
    shared_lib = shared_library(libname,
            sources,
            #objects: objs,
            c_args: cflags,
            dependencies: shared_deps,
            include_directories: includes,
            #version: abi_version,
            #soversion: so_version,
            install: true)
    shared_dep = declare_dependency(link_with: shared_lib,
            include_directories: includes,
            dependencies: shared_deps)

    tldk_libraries = [shared_lib] + tldk_libraries
    tldk_static_libraries = [static_lib] + tldk_static_libraries

    set_variable('shared_tle_' + name, shared_dep)
    set_variable('static_tle_' + name, static_dep)
    if developer_mode
        message('lib/@0@: Defining dependency "@1@"'.format(l, name))
    endif
endforeach
