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
LIB = libtle_l4p.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR)

EXPORT_MAP := tle_l4p_version.map

LIBABIVER := 1

#source files
SRCS-y += ctx.c
SRCS-y += event.c
SRCS-y += stream_table.c
SRCS-y += tcp_ofo.c
SRCS-y += tcp_stream.c
SRCS-y += tcp_rxtx.c
SRCS-y += udp_stream.c
SRCS-y += udp_rxtx.c

# install this header file
SYMLINK-y-include += tle_ctx.h
SYMLINK-y-include += tle_event.h
SYMLINK-y-include += tle_tcp.h
SYMLINK-y-include += tle_udp.h

# this lib dependencies
DEPDIRS-y += lib/libtle_dring
DEPDIRS-y += lib/libtle_timer

include $(TLDK_ROOT)/mk/tle.lib.mk
