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

LIB_SHARED = $(LIB_NAME).so
LIB_STATIC = $(LIB_NAME).a

LDFLAGS += -Wl,--no-undefined $(LDFLAGS_SHARED)

ifneq ($(LIB_DEPS),)
	LDLIBS += -L$(RTE_OUTPUT)/lib
	LDLIBS += $(patsubst %,-l%,$(LIB_DEPS))
	LDFLAGS += $(LDLIBS)
endif

.PHONY: all clean static shared
all: shared static
shared: $(RTE_OUTPUT)/lib/$(LIB_SHARED)
static: $(RTE_OUTPUT)/lib/$(LIB_STATIC)

OBJS := $(patsubst %.c,$(BDIR)/%.o,$(SRCS-y))

$(BDIR)/%.o: %.c Makefile $(HDRS) $(PC_FILE)
	@mkdir -p $(BDIR)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

HDRS := $(patsubst %.h,$(RTE_OUTPUT)/include/%.h,$(SYMLINK-y-include))

$(RTE_OUTPUT)/include/%.h: %.h Makefile $(PC_FILE)
	$(Q)ln -s -f $(RTE_SRCDIR)/$< $@

clean:
	$(Q)rm -f $(RTE_OUTPUT)/lib/$(LIB_SHARED)
	$(Q)rm -f $(RTE_OUTPUT)/lib/$(LIB_STATIC)
	$(Q)rm -f $(HDRS)
	$(Q)rm -rf $(BDIR)

$(RTE_OUTPUT)/lib/$(LIB_SHARED): $(HDRS) $(OBJS) Makefile $(PC_FILE)
ifneq ($(OBJS),)
	$(Q)$(CC) $(OBJS) -o $@ -shared $(LDFLAGS)
endif

$(RTE_OUTPUT)/lib/$(LIB_STATIC): $(HDRS) $(OBJS) Makefile $(PC_FILE)
ifneq ($(OBJS),)
	$(Q)$(AR) -cr $@ $(OBJS) -o $@
endif
