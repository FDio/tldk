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

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overwritten by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = libtle_udp.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR)

EXPORT_MAP := tle_udp_version.map

LIBABIVER := 1

#source files
SRCS-y += event.c
SRCS-y += udp_ctl.c
SRCS-y += udp_rxtx.c

# install this header file
SYMLINK-y-include += tle_udp_impl.h
SYMLINK-y-include += tle_event.h

# this lib dependencies
DEPDIRS-y += lib/libtle_dring

include $(RTE_SDK)/mk/rte.extlib.mk
