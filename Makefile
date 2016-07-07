# Copyright (c) 2016 Intel Corporation.
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

TLDK_ROOT := $(CURDIR)
export TLDK_ROOT

DPDK_VERSION=16.04
LOCAL_RTE_SDK=$(TLDK_ROOT)/dpdk/_build/dpdk-$(DPDK_VERSION)/

ifeq ($(RTE_SDK),)
	export RTE_SDK=$(LOCAL_RTE_SDK)
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

DIRS-y += lib
DIRS-y += examples
DIRS-y += test

MAKEFLAGS += --no-print-directory

# output directory
O ?= $(TLDK_ROOT)/${RTE_TARGET}
BASE_OUTPUT ?= $(abspath $(O))

.PHONY: all
all: $(DIRS-y)

.PHONY: clean
clean: $(DIRS-y)

.PHONY: $(DIRS-y)
$(DIRS-y): $(RTE_SDK)/mk/rte.vars.mk
	@echo "== $@"
	$(Q)$(MAKE) -C $(@) \
		M=$(CURDIR)/$(@)/Makefile \
		O=$(BASE_OUTPUT) \
		BASE_OUTPUT=$(BASE_OUTPUT) \
		CUR_SUBDIR=$(CUR_SUBDIR)/$(@) \
		S=$(CURDIR)/$(@) \
		RTE_TARGET=$(RTE_TARGET) \
		$(filter-out $(DIRS-y),$(MAKECMDGOALS))

$(RTE_SDK)/mk/rte.vars.mk:
ifeq ($(RTE_SDK),$(LOCAL_RTE_SDK)) 
	@make RTE_TARGET=$(RTE_TARGET) config all -C $(TLDK_ROOT)/dpdk/
endif

