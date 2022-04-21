# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2016-2022 Intel Corporation

# This file is heavily based on the DPDK implementation

link_whole_libs = []
if get_option('default_library') == 'static'
    link_whole_libs = tldk_static_libraries
endif

# list of all example apps. Keep 1-3 per line, in alphabetical order.
all_examples = [
        'l4fwd',
]

default_cflags = ['-march=native', '-mno-avx512f', '-fPIC']
if cc.has_argument('-Wno-format-truncation')
    default_cflags += '-Wno-format-truncation'
endif

default_ldflags = tldk_extra_ldflags
if get_option('default_library') == 'static'
    default_ldflags += ['-Wl,--export-dynamic']
endif

# future could add selective similar to DPDK here
examples = all_examples

foreach example: examples
    name = example
    build = true
    sources = []
    includes = [include_directories(example)]
    cflags = default_cflags
    ldflags = default_ldflags

    ext_deps = [libdpdk_dep]
    deps = ['l4p']

    subdir(example)

    if build
        dep_objs = ext_deps
        foreach d:deps
            var_name = get_option('default_library') + '_tle_' + d
            if not is_variable(var_name)
                build = false
                message('Missing dependency "@0@" for example "@1@"'.format(d, name))
                break
            endif
            dep_objs += [get_variable(var_name)]
        endforeach
    endif

    if not build
        message('Skipping example "' + name + '"')
        continue
    endif

    executable('tldk-' + name,
            sources,
            c_args: cflags,
            include_directories: includes,
            link_with: link_whole_libs,
            link_args: ldflags,
            dependencies: dep_objs)
endforeach
