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

APP_SHARED = $(APP_NAME)-shared
APP_STATIC = $(APP_NAME)-static

ifneq ($(LIB_DEPS),)
	LDLIBS += -L$(RTE_OUTPUT)/lib
	LDLIBS_SHARED += $(patsubst %,-l%,$(LIB_DEPS))
	LDLIBS_STATIC += $(patsubst %,-l:lib%.a,$(LIB_DEPS))
	LDFLAGS_SHARED += $(LDLIBS) $(LDLIBS_SHARED)
	LDFLAGS_STATIC += $(LDLIBS) $(LDLIBS_STATIC)
endif

.PHONY: all clean static shared
all: shared static
shared: $(RTE_OUTPUT)/app/$(APP_SHARED)
static: $(RTE_OUTPUT)/app/$(APP_STATIC)

OBJS += $(patsubst %.c,$(BDIR)/%.o,$(SRCS-y))

$(BDIR)/%.o: %.c Makefile $(PC_FILE)
	@mkdir -p $(BDIR)
	$(Q)$(CC) $(CFLAGS) $(CFLAGS_$(<)) -c $< -o $@

SCRIPTS := $(patsubst %,$(RTE_OUTPUT)/app/%,$(SYMLINK-y-app))

$(RTE_OUTPUT)/app/%.py: %.py Makefile
	$(Q)ln -s -f $(RTE_SRCDIR)/$< $@

clean:
	$(Q)rm -f $(RTE_OUTPUT)/app/$(APP_SHARED)
	$(Q)rm -f $(RTE_OUTPUT)/app/$(APP_STATIC)
	$(Q)rm -f $(RTE_OUTPUT)/app/$(APP_NAME)
	$(Q)rm -f $(SCRIPTS)
	$(Q)rm -rf $(BDIR)

$(RTE_OUTPUT)/app/$(APP_SHARED): $(SCRIPTS) $(OBJS) Makefile $(PC_FILE)
ifneq ($(OBJS),)
	$(Q)$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)
endif

$(RTE_OUTPUT)/app/$(APP_STATIC): $(SCRIPTS) $(OBJS) Makefile $(PC_FILE)
ifneq ($(OBJS),)
	$(Q)$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)
	$(Q)ln -s -f $@ $(RTE_OUTPUT)/app/$(APP_NAME)
endif
