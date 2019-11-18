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

EXTLIB_BUILD := y

ifneq ($(HACK_CC),)
CC = $(HACK_CC)
endif

# we must create the output dir first and recall the same Makefile
# from this directory
ifeq ($(NOT_FIRST_CALL),)

NOT_FIRST_CALL = 1
export NOT_FIRST_CALL

BDIR := $(RTE_OUTPUT)/build/$(CUR_SUBDIR)

all:
	$(Q)mkdir -p $(BDIR)
	$(Q)$(MAKE) -C $(BDIR) -f $(RTE_EXTMK) \
		S=$(RTE_SRCDIR) O=$(RTE_OUTPUT) SRCDIR=$(RTE_SRCDIR)

%::
	$(Q)mkdir -p $(BDIR)
	$(Q)$(MAKE) -C $(BDIR) -f $(RTE_EXTMK) $@ \
		S=$(RTE_SRCDIR) O=$(RTE_OUTPUT) SRCDIR=$(RTE_SRCDIR)
else
include $(RTE_SDK)/mk/rte.lib.mk
endif
