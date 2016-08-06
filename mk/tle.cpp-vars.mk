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

ifeq ($(RTE_TOOLCHAIN), clang)
CXX = $(CROSS)clang++
ifeq ("$(origin CXX)", "command line")
HOSTCXX = $(CXX)
else
HOSTCXX = clang++
endif
endif

ifeq ($(RTE_TOOLCHAIN), icc)
CXX = icc
ifeq ("$(origin CXX)", "command line")
HOSTCXX = $(CXX)
else
HOSTCXX = icc
endif
endif

ifeq ($(RTE_TOOLCHAIN), gcc)
CXX = $(CROSS)g++
ifeq ("$(origin CXX)", "command line")
HOSTCXX = $(CXX)
else
HOSTCXX = g++
endif
endif

TOOLCHAIN_CXXFLAGS =

CXXFLAGS := $(CFLAGS)

export CXX CXXFLAGS TOOLCHAIN_CXXFLAGS
