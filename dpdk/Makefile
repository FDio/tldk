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

RTE_OUTPUT ?= $(O)

DOWNLOAD_DIR := $(CURDIR)/downloads
MESON_DIR := $(CURDIR)/meson

DPDK_VERSION          ?= 20.11
DPDK_SRC_DIR          ?= $(RTE_OUTPUT)-src
DPDK_BUILD_DIR        ?= $(RTE_OUTPUT)-build
DPDK_INSTALL_DIR      ?= $(RTE_OUTPUT)
DPDK_MARCH            ?= native
DPDK_BUILD            ?= release

S := $(DPDK_SRC_DIR)
B := $(DPDK_BUILD_DIR)
I := $(DPDK_INSTALL_DIR)

DPDK_GIT_REPO ?= http://dpdk.org/git/dpdk-stable

JOBS := $(shell grep processor /proc/cpuinfo | wc -l)

all: build

$(S)/.download.ok:
	@if [ -e $(S) ] ; \
		then rm -rf $(S) ; \
	fi
	$(Q)git clone $(DPDK_GIT_REPO) --branch $(DPDK_VERSION) $(S)
	@touch $@

.PHONY: download
download: $(S)/.download.ok

$(S)/.patch.ok: $(S)/.download.ok
ifneq ($(wildcard $(CURDIR)/dpdk-$(DPDK_VERSION)_patches/*.patch),)
	@echo --- patching ---
	for f in $(CURDIR)/dpdk-$(DPDK_VERSION)_patches/*.patch ; do \
		echo Applying patch: $$(basename $$f) ; \
		patch -p1 -d $(S) < $$f ; \
	done
endif
	@touch $@

.PHONY: patch
patch: $(S)/.patch.ok

$(MESON_DIR)/meson.ok:
	$(Q)mkdir -p $(DOWNLOAD_DIR)
	$(Q)mkdir -p $(MESON_DIR)
	$(Q)python3 -m venv $(MESON_DIR)
	$(Q)pip3 download -d $(DOWNLOAD_DIR) \
		meson==0.55 setuptools wheel pyelftools
	$(Q)source $(MESON_DIR)/bin/activate && \
	pip3 install --no-index \
		--find-links=$(DOWNLOAD_DIR) --target=$(MESON_DIR) \
		meson==0.55 pyelftools && \
	deactivate
	@touch $@

.PHONY: config
config: patch $(MESON_DIR)/meson.ok
	$(Q)source $(MESON_DIR)/bin/activate && \
	meson --prefix=$(I) --werror -Dtests=false \
		-Dbuildtype=$(DPDK_BUILD) -Dmachine=$(DPDK_MARCH) $(B) $(S) && \
	deactivate

.PHONY: build
build: config $(B)/build.ninja
	$(Q)source $(MESON_DIR)/bin/activate && \
	meson install -C $(B) && \
	deactivate

.PHONY: clean
clean:
	$(Q)rm -rf $(B) $(I) $(S)
