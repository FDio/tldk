# Copyright (c) 2018 Ant Financial Services Group.
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
LIB = libtle_glue.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR)

EXPORT_MAP := tle_glue_version.map

LIBABIVER := 1

# source files
SRCS-y += fd.c
SRCS-y += ctx.c
SRCS-y += arp.c
SRCS-y += icmp.c
SRCS-y += rxcb.c
SRCS-y += port.c
SRCS-y += sym.c
SRCS-y += init.c
SRCS-y += be.c
SRCS-y += epoll.c
SRCS-y += socket.c
SRCS-y += rxtx.c
SRCS-y += poll.c
SRCS-y += util.c
SRCS-y += tcp.c
SRCS-y += udp.c
SRCS-y += select.c

ifeq ($(PACKETDRILL),y)
SRCS-y += packetdrill.c
endif

# install this header file
SYMLINK-y-include += tle_glue.h

# this lib dependencies
DEPDIRS-y += lib/libtle_l4p

include $(TLDK_ROOT)/mk/tle.lib.mk
