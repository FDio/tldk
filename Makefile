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

RTE_TARGET ?= x86_64-native-linuxapp-gcc

LOCAL_RTE_SDK=$(TLDK_ROOT)/dpdk/$(RTE_TARGET)

ifeq ($(RTE_SDK),)
	export RTE_SDK=$(LOCAL_RTE_SDK)
endif

RTE_PKG_CONF=$(RTE_SDK)/lib/x86_64-linux-gnu/pkgconfig

DIRS-y += lib
DIRS-y += examples
DIRS-y += test

MAKEFLAGS += --no-print-directory

# output directory
O ?= $(TLDK_ROOT)/${RTE_TARGET}
BASE_OUTPUT ?= $(abspath $(O))

.PHONY: all
all: $(BASE_OUTPUT) $(DIRS-y)

.PHONY: clean
clean: $(DIRS-y) $(RTE_PKG_CONF)
	$(Q)rm -rf $(BASE_OUTPUT)
ifeq ($(RTE_SDK),$(LOCAL_RTE_SDK))
	$(Q)make $(@) -C $(TLDK_ROOT)/dpdk O=$(RTE_SDK)
endif

examples test: lib

.PHONY: $(DIRS-y)
$(DIRS-y): $(RTE_PKG_CONF)
	@echo "== $@"
	$(Q)$(MAKE) -C $(@) \
		M=$(CURDIR)/$(@)/Makefile \
		O=$(BASE_OUTPUT) \
		S=$(CURDIR)/$(@) \
		RTE_TARGET=$(RTE_TARGET) \
		$(filter-out $(DIRS-y),$(MAKECMDGOALS))

$(BASE_OUTPUT):
	$(Q)mkdir -p $(BASE_OUTPUT)/lib
	$(Q)mkdir -p $(BASE_OUTPUT)/include
	$(Q)mkdir -p $(BASE_OUTPUT)/app

$(RTE_PKG_CONF):
ifeq ($(RTE_SDK),$(LOCAL_RTE_SDK))
	@echo "== $@"
	$(Q)make -C $(TLDK_ROOT)/dpdk O=$(RTE_SDK) 
endif
