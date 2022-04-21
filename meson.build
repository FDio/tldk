# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2016-2022 Intel Corporation

project('TLDK', 'C',
        # Get version number from file.
        # Fallback to "more" for Windows compatibility.
        version: run_command(find_program('cat', 'more'),
            files('VERSION'), check: true).stdout().strip(),
        license: 'Apache-2.0',
        default_options: [
            'buildtype=release',
            'cpp_std=c++11',
            'default_library=static',
            'warning_level=2',
        ],
        meson_version: '>= 0.55.0'
)

# check for developer mode
developer_mode = false
if get_option('developer_mode').auto()
    if meson.version().version_compare('>=0.53') # fs module available
        fs = import('fs')
        developer_mode = fs.is_dir('.git')
    endif
else
    developer_mode = get_option('developer_mode').enabled()
endif
if developer_mode
    message('## Building in Developer Mode ##')
endif

# set up some global vars for compiler, platform, configuration, etc.
cc = meson.get_compiler('c')
tldk_source_root = meson.current_source_dir()
tldk_build_root = meson.current_build_dir()
tldk_conf = configuration_data()
tldk_libraries = []
tldk_static_libraries = []
tldk_extra_ldflags = []

global_inc = []

# configuration + external/3p deps
subdir('config')

# build libs
subdir('lib')

# build binaries and installable tools
subdir('app')

# build docs
# TODO doxygen
#if get_option('docs')
    #subdir('doc')
#endif

# build examples
if get_option('examples')
    subdir('examples')
endif
