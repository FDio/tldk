# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2016-2022 Intel Corporation


# check for dpdk 
# the fallback dpdk is a minimal set of libraries and drivers with just enough support
# for the tests and some example applications. if using in production, it is
# recommended that you provide your own build/installation of DPDK.
dpdk_disable_libs = [
    'bitratestats',
    'gpudev',
    'jobstats',
    'kni',
    'latencystats',
    'metrics',
    'power',
    'vhost',
]
dpdk_disable_libs_opt = 'disable_libs=@0@'.format(','.join(dpdk_disable_libs))
dpdk_disable_drivers = [
    'common/cnxk',
    'common/cpt',
    'common/dpaax',
    'common/mvep',
    'common/mlx5',
    'common/octeontx',
    'common/octeontx2',
    'common/sfc_efx',
    'common/qat',
    'bus/auxiliary',
    'bus/dpaa',
    'bus/fslmc',
    'bus/ifpga',
    'bus/vmbus',
    'mempool/cnxk',
    'mempool/dpaa',
    'mempool/dpaa2',
    'mempool/octeontx',
    'mempool/octeontx2',
    'dma/skeleton',
    'dma/cnxk',
    'dma/dpaa',
    'dma/hisilicon',
    'dma/idxd',
    'dma/ioat',
    'net/af_xdp',
    'net/ark',
    'net/atlantic',
    'net/avp',
    'net/axgbe',
    'net/bonding',
    'net/bnx2x',
    'net/bnxt',
    'net/cnxk',
    'net/cxgbe',
    'net/dpaa',
    'net/dpaa2',
    'net/e1000',
    'net/ena',
    'net/enetc',
    'net/enetfec',
    'net/enic',
    'net/failsafe',
    'net/fm10k',
    'net/hinic',
    'net/hns3',
    'net/ice',
    'net/igc',
    'net/ionic',
    'net/ipn3ke',
    'net/ixgbe',
    'net/kni',
    'net/liquidio',
    'net/memif',
    'net/mlx4',
    'net/mlx5',
    'net/mvneta',
    'net/mvpp2',
    'net/netvsc',
    'net/ngbe',
    'net/nfb',
    'net/nfp',
    'net/null',
    'net/octeontx',
    'net/octeontx2',
    'net/octeontx_ep',
    'net/pfe',
    'net/qede',
    'net/sfc',
    'net/softnic',
    'net/szedata2',
    'net/thunderx',
    'net/txgbe',
    'net/vdev_netvsc',
    'net/vhost',
    'raw/cnxk_bphy',
    'raw/dpaa2_cmdif',
    'raw/dpaa2_qdma',
    'raw/ifpga',
    'raw/ioat',
    'raw/ntb',
    'raw/octeontx2_dma',
    'raw/octeontx2_ep',
    'raw/skeleton',
    'crypto/aesni_gcm',
    'crypto/aesni_mb',
    'crypto/armv8',
    'crypto/bcmfs',
    'crypto/caam_jr',
    'crypto/ccp',
    'crypto/cnxk',
    'crypto/dpaa_sec',
    'crypto/dpaa2_sec',
    'crypto/ipsec_mb',
    'crypto/kasumi',
    'crypto/mlx5',
    'crypto/mvsam',
    'crypto/nitrox',
    'crypto/null',
    'crypto/octeontx',
    'crypto/octeontx2',
    'crypto/openssl',
    'crypto/scheduler',
    'crypto/snow3g',
    'crypto/virtio',
    'crypto/zuc',
    'compress/octeontx',
    'compress/isal',
    'compress/mlx5',
    'compress/zlib',
    'regex/mlx5',
    'regex/octeontx2',
    'vdpa/ifc',
    'vdpa/mlx5',
    'vdpa/sfc',
    'event/cnxk',
    'event/dpaa',
    'event/dpaa2',
    'event/octeontx',
    'event/octeontx2',
    'event/opdl',
    'event/skeleton',
    'baseband/acc100',
    'baseband/fpga_5gnr_fec',
    'baseband/fpga_lte_fec',
    'baseband/la12xx',
    'baseband/null',
    'baseband/turbo_sw',
    'gpu/cuda',
]
dpdk_disable_drivers_opt = 'disable_drivers=@0@'.format(','.join(dpdk_disable_drivers))
libdpdk_dep = dependency(
    'libdpdk',
    required: true,
    fallback: ['dpdk', 'dpdk_dep'],
    default_options: [
      'default_library=static',
      'tests=false',
      dpdk_disable_libs_opt,
      dpdk_disable_drivers_opt,
    ],
    static: true
)


# check for gtest
gtest_dep = dependency('gtest', required: false, fallback: ['gtest', 'gtest_dep'])
gmock_dep = dependency('gmock', required: false, fallback: ['gtest', 'gmock_dep'])


# python3 + scapy -- needed for unit tests
py3_dep = import('python').find_installation('python',
    required: false,
    modules : ['scapy'])

if get_option('tests')
    test_deps_found = true
    if (not gtest_dep.found())
        test_deps_found = false
        warning('Test dependency \'gtest\' not found but tests are requested')
    endif

    if (not py3_dep.found())
        test_deps_found = false
        warning('Test dependency \'python3\' not found but tests are requested')
    endif

    if (not test_deps_found)
        error('Dependencies for building/running tests were not found.')
    endif
endif



# enable extra warnings and disable any unwanted warnings
warning_flags = [
        # -Wall is added by meson by default, so add -Wextra only
        '-Wextra',

        # additional warnings in alphabetical order
        '-Wcast-qual',
        '-Wdeprecated',
        '-Wformat',
        '-Wformat-nonliteral',
        '-Wformat-security',
        '-Wmissing-declarations',
        '-Wmissing-prototypes',
        '-Wnested-externs',
        '-Wold-style-definition',
        '-Wpointer-arith',
        '-Wsign-compare',
        '-Wstrict-prototypes',
        '-Wundef',
        '-Wwrite-strings',

        # globally disabled warnings
        '-Wno-address-of-packed-member',
        '-Wno-packed-not-aligned',
        '-Wno-missing-field-initializers',
]
foreach arg: warning_flags
    if cc.has_argument(arg)
        add_project_arguments(arg, language: 'c')
    endif
    if cpp.has_argument(arg)
        add_project_arguments(arg, language: 'cpp')
    endif
endforeach
