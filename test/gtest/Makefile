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

ifeq ($(GTEST_DIR),)
all:
	@echo "GTEST_DIR is not setup properly. Skipping gtest"

%::
	@echo "GTEST_DIR is not setup properly. Skipping gtest"

else

# binary name
APP_NAME = gtest-rfc

include $(TLDK_ROOT)/mk/tle.var.mk

# all source are stored in SRCS-y
SRCCPP-y += main.cpp
SRCCPP-y += test_common.cpp
SRCCPP-y += test_tle_dring.cpp
SRCCPP-y += test_tle_ctx.cpp
SRCCPP-y += test_tle_udp_destroy.cpp
SRCCPP-y += test_tle_udp_event.cpp
SRCCPP-y += test_tle_udp_stream_gen.cpp
SRCCPP-y += test_tle_tcp_stream.cpp

SYMLINK-y-app += test_scapy_gen.py

CXXFLAGS += -std=c++11

CXXFLAGS += -I$(GTEST_DIR)/include
CXXFLAGS += -I$(GMOCK_DIR)/include

CXXFLAGS += $(CFLAGS) -Wno-error

LDFLAGS += -lstdc++ -lpthread
LDFLAGS += -L$(GMOCK_DIR) -L$(GMOCK_DIR)/../lib -lgmock
LDFLAGS += -L$(GMOCK_DIR)/gtest -L$(GMOCK_DIR)/../lib -lgtest

LIB_DEPS += tle_l4p
LIB_DEPS += tle_memtank
LIB_DEPS += tle_timer
LIB_DEPS += tle_dring

CPP_OBJS := $(patsubst %.cpp,$(BDIR)/%.o,$(SRCCPP-y))
OBJS += $(CPP_OBJS)

$(BDIR)/%.o: %.cpp Makefile
	@mkdir -p $(BDIR)
	$(Q)$(CXX) $(CXXFLAGS) $(CXXFLAGS_$(<)) -c $< -o $@

include $(TLDK_ROOT)/mk/tle.app.mk

endif
