# Copyright (c) 2015 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Scripts require non-POSIX parts of bash
SHELL := /bin/bash

DPDK_VERSION ?= 16.07
DPDK_BUILD_DIR        ?= $(CURDIR)/_build
DPDK_INSTALL_DIR      ?= $(DPDK_BUILD_DIR)/dpdk/$(RTE_TARGET)
DPDK_PKTMBUF_HEADROOM ?= 128
DPDK_MARCH            ?= native
DPDK_TUNE             ?= generic
DPDK_DEBUG            ?= n

B := $(DPDK_BUILD_DIR)
I := $(DPDK_INSTALL_DIR)
DPDK_GIT_REPO ?= http://dpdk.org/git/dpdk
DPDK_SOURCE := $(B)/dpdk

ifneq (,$(findstring clang,$(CC)))
DPDK_CC=clang
else
DPDK_CC=gcc
endif

ifeq (,$(DPDK_TARGET))
DPDK_TARGET := x86_64-native-linuxapp-$(DPDK_CC)
endif

JOBS := $(shell grep processor /proc/cpuinfo | wc -l)

# compiler/linker custom arguments
DPDK_CPU_CFLAGS := -pie -fPIC
DPDK_CPU_LDFLAGS :=
DPDK_EXTRA_LDFLAGS := -g

ifeq ($(DPDK_DEBUG),n)
DPDK_EXTRA_CFLAGS := -g -mtune=$(DPDK_TUNE)
else
DPDK_EXTRA_CFLAGS := -g -O0
endif

# translate gcc march values to DPDK arch
ifeq ($(DPDK_MARCH),native)
DPDK_MACHINE:=native                     # autodetect host CPU
else ifeq ($(DPDK_MARCH),corei7)
DPDK_MACHINE:=nhm                        # Nehalem / Westmere
else ifeq ($(DPDK_MARCH),corei7-avx)
DPDK_MACHINE:=snb                        # Sandy Bridge
else ifeq ($(DPDK_MARCH),core-avx-i)
DPDK_MACHINE:=ivb                        # Ivy Bridge
else ifeq ($(DPDK_MARCH),core-avx2)
DPDK_MACHINE:=hsw                        # Haswell
else ifeq ($(DPDK_MARCH),armv7a)
DPDK_MACHINE:=armv7a                     # ARMv7
else ifeq ($(DPDK_MARCH),armv8a)
DPDK_MACHINE:=armv8a                     # ARMv8
else
$(error Unknown DPDK_MARCH)
endif

# assemble DPDK make arguments
DPDK_MAKE_ARGS := -C $(DPDK_SOURCE) -j $(JOBS) \
	T=$(DPDK_TARGET) \
	RTE_CONFIG_TEMPLATE=../custom-config \
	RTE_OUTPUT=$(I) \
	EXTRA_CFLAGS="$(DPDK_EXTRA_CFLAGS)" \
	EXTRA_LDFLAGS="$(DPDK_EXTRA_LDFLAGS)" \
	CPU_CFLAGS="$(DPDK_CPU_CFLAGS)" \
	CPU_LDFLAGS="$(DPDK_CPU_LDFLAGS)" \
        $(DPDK_MAKE_EXTRA_ARGS)

DPDK_SOURCE_FILES := $(shell  [ -e $(DPDK_SOURCE) ] && \
						find $(DPDK_SOURCE) -name "*.[chS]")

define set
@if grep -q CONFIG_$1 $@ ; \
	then sed -i -e 's/.*\(CONFIG_$1=\).*/\1$2/' $@ ; \
	else echo CONFIG_$1=$2 >> $@ ; \
fi
endef

all: build

$(B)/custom-config: $(B)/.patch.ok Makefile
	@echo --- generating custom config from \
		$(DPDK_SOURCE)/config/defconfig_$(DPDK_TARGET) --- $@
	@cpp -undef -ffreestanding -x assembler-with-cpp \
		$(DPDK_SOURCE)/config/defconfig_$(DPDK_TARGET) $@
	$(call set,RTE_MACHINE,$(DPDK_MACHINE))
	@# modify options
	$(call set,RTE_MAX_LCORE,256)
	$(call set,RTE_PKTMBUF_HEADROOM,$(DPDK_PKTMBUF_HEADROOM))
	$(call set,RTE_LIBEAL_USE_HPET,y)
	$(call set,RTE_BUILD_COMBINE_LIBS,y)
	$(call set,RTE_LIBRTE_I40E_16BYTE_RX_DESC,y)
	$(call set,RTE_LIBRTE_I40E_ITR_INTERVAL,16)
	$(call set,RTE_LIBRTE_PMD_PCAP,y)
	@# enable debug init for device drivers
	$(call set,RTE_LIBRTE_I40E_DEBUG_INIT,$(DPDK_DEBUG))
	$(call set,RTE_LIBRTE_IXGBE_DEBUG_INIT,$(DPDK_DEBUG))
	$(call set,RTE_LIBRTE_E1000_DEBUG_INIT,$(DPDK_DEBUG))
	$(call set,RTE_LIBRTE_VIRTIO_DEBUG_INIT,$(DPDK_DEBUG))
	$(call set,RTE_LIBRTE_VMXNET3_DEBUG_INIT,$(DPDK_DEBUG))
	$(call set,RTE_LIBRTE_PMD_BOND,y)
	$(call set,RTE_LIBRTE_IP_FRAG,y)
	@# not needed
	$(call set,RTE_LIBRTE_TIMER,n)
	$(call set,RTE_LIBRTE_CFGFILE,n)
	$(call set,RTE_LIBRTE_LPM,y)
	$(call set,RTE_LIBRTE_ACL,n)
	$(call set,RTE_LIBRTE_POWER,n)
	$(call set,RTE_LIBRTE_DISTRIBUTOR,n)
	$(call set,RTE_LIBRTE_REORDER,n)
	$(call set,RTE_LIBRTE_PORT,n)
	$(call set,RTE_LIBRTE_TABLE,n)
	$(call set,RTE_LIBRTE_PIPELINE,n)
	$(call set,RTE_KNI_KMOD,n)
	@rm -f .config.ok

$(B)/.download.ok:
	@mkdir -p $(B)
	@if [ -e $(DPDK_SOURCE) ] ; \
		then rm -rf $(DPDK_SOURCE) ; \
	fi
ifeq ($(DPDK_VERSION),master)
	@git clone $(DPDK_GIT_REPO) --branch $(DPDK_VERSION) $(DPDK_SOURCE)
else
	@git clone $(DPDK_GIT_REPO) --branch v$(DPDK_VERSION) $(DPDK_SOURCE)
endif
	@touch $@

.PHONY: download
download: $(B)/.download.ok

$(B)/.patch.ok: $(B)/.download.ok
ifneq ($(wildcard $(CURDIR)/dpdk-$(DPDK_VERSION)_patches/*.patch),)
	@echo --- patching ---
	for f in $(CURDIR)/dpdk-$(DPDK_VERSION)_patches/*.patch ; do \
		echo Applying patch: $$(basename $$f) ; \
		patch -p1 -d $(DPDK_SOURCE) < $$f ; \
	done
endif
	@touch $@

.PHONY: patch
patch: $(B)/.patch.ok

$(B)/.config.ok: $(B)/.patch.ok $(B)/custom-config
	@make $(DPDK_MAKE_ARGS) config
	@touch $@

.PHONY: config
config: $(B)/.config.ok

$(B)/.build.ok: $(DPDK_SOURCE_FILES)
	@if [ ! -e $(B)/.config.ok ] ; then echo 'Please run "make config" \
		first' && false ; fi
	@make $(DPDK_MAKE_ARGS) install
	@cp $(I)/.config $(B)/.config
	@touch $@

.PHONY: build
build: $(B)/.build.ok

.PHONY: clean
clean:
	@rm -rf $(B) $(I)
