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

# binary name
APP_NAME = l4fwd

include $(TLDK_ROOT)/mk/tle.var.mk

# all source are stored in SRCS-y
SRCS-y += parse.c
SRCS-y += pkt.c
SRCS-y += main.c

LIB_DEPS += tle_l4p
LIB_DEPS += tle_memtank
LIB_DEPS += tle_timer

CFLAGS_parse.c += -D_GNU_SOURCE
CFLAGS_main.c += -D_GNU_SOURCE

include $(TLDK_ROOT)/mk/tle.app.mk
