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

LOCAL_RTE_SDK=$(TLDK_ROOT)/dpdk/_build/dpdk

ifeq ($(RTE_SDK),)
	export RTE_SDK=$(LOCAL_RTE_SDK)
endif

RTE_TARGET ?= x86_64-native-linuxapp-gcc

DIRS-y += dpdk
DIRS-y += lib
DIRS-y += examples
DIRS-y += test

MAKEFLAGS += --no-print-directory

# output directory
O ?= $(TLDK_ROOT)/${RTE_TARGET}
BASE_OUTPUT ?= $(abspath $(O))

DPDK_LIBS_PATH := $(TLDK_ROOT)/dpdk/install/lib
TLDK_LIBS_PATH := $(TLDK_ROOT)/$(RTE_TARGET)/lib
LIBS :=

.PHONY: all
all: $(DIRS-y)

.PHONY: clean
clean:
	@make clean -C test/packetdrill
	@rm -rf $(RTE_TARGET)
	@rm -rf libtldk.so libtldk.a

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
		EXTRA_CFLAGS="-fPIC" \
		$(filter-out $(DIRS-y),$(MAKECMDGOALS))

test: libtldk.a libtldk.so

libtldk.so: lib
	$(eval LIBS = $(wildcard $(DPDK_LIBS_PATH)/librte*.a $(TLDK_LIBS_PATH)/*.a))
	@gcc -shared -o libtldk.so -L$(DPDK_LIBS_PATH) -L$(TLDK_LIBS_PATH) \
		-Wl,--whole-archive $(LIBS) -Wl,--no-whole-archive \
		-lpthread -ldl -lnuma

define repack
@echo -- repack $1 ---
@rm -rf tmpxyz; rm -f $1; mkdir tmpxyz; cd tmpxyz;	\
	for f in $(LIBS) ; do				\
		fn=$$(basename $$f) ;			\
		echo $$fn ;				\
		mkdir $$fn"_obj" ;			\
		cd $$fn"_obj" ;				\
		ar x $$f ;				\
		cd .. ;					\
	done;						\
ar cru ../$1 $$(find */*.o | paste -sd " " -); cd ..; rm -rf tmpxyz
endef

libtldk.a: lib
	$(eval LIBS = $(wildcard $(DPDK_LIBS_PATH)/librte*.a))
	$(call repack,libdpdk.a)
	$(eval LIBS = $(wildcard $(DPDK_LIBS_PATH)/librte*.a $(TLDK_LIBS_PATH)/*.a))
	$(call repack,libtldk.a)

$(RTE_SDK)/mk/rte.vars.mk:
ifeq ($(RTE_SDK),$(LOCAL_RTE_SDK))
	@make RTE_TARGET=$(RTE_TARGET) config all -C $(TLDK_ROOT)/dpdk/
endif
