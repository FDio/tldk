# Copyright (c) 2021 Intel Corporation.
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
RTE_OUTPUT ?= $(O)
RTE_SRCDIR ?= $(S)

PKGCONF = export PKG_CONFIG_PATH=$(RTE_SDK)/lib/x86_64-linux-gnu/pkgconfig; \
	   pkg-config
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
	$(error "no installation of DPDK found")
endif

CFLAGS += -O3
CFLAGS += -fPIC
CFLAGS += -m64 -pthread
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -I$(RTE_OUTPUT)/include

# compiler errors/warnings
ifeq ($(CC), clang)
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -Wno-missing-field-initializers -Wno-implicit-fallthrough
CFLAGS += -Wno-address-of-packed-member -Wno-gnu-alignof-expression
CFLAGS += -Wno-constant-conversion
else
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -Wno-missing-field-initializers -Wimplicit-fallthrough=2
CFLAGS += -Wno-format-truncation -Wno-address-of-packed-member
endif

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

ifneq ($(APP_NAME),)
	BDIR := $(RTE_OUTPUT)/build/$(APP_NAME)
else
	BDIR := $(RTE_OUTPUT)/build/$(LIB_NAME)
endif
