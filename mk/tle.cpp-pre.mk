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

# convert source to obj file
src2obj = $(strip $(patsubst %.cpp,%.o,\
        $(patsubst %.S,%_s.o,$(1))))

# add a dot in front of the file name
dotfile = $(strip $(foreach f,$(1),\
        $(join $(dir $f),.$(notdir $f))))

# convert source/obj files into dot-dep filename (does not
# include .S files)
src2dep = $(strip $(call dotfile,$(patsubst %.cpp,%.o.d, \
                $(patsubst %.S,,$(1)))))
obj2dep = $(strip $(call dotfile,$(patsubst %.o,%.o.d,$(1))))

# convert source/obj files into dot-cmd filename
src2cmd = $(strip $(call dotfile,$(patsubst %.cpp,%.o.cmd, \
                $(patsubst %.S,%_s.o.cmd,$(1)))))
obj2cmd = $(strip $(call dotfile,$(patsubst %.o,%.o.cmd,$(1))))

OBJS-y := $(call src2obj,$(SRCS-y))
OBJS-n := $(call src2obj,$(SRCS-n))
OBJS-  := $(call src2obj,$(SRCS-))
OBJS-all := $(filter-out $(SRCS-all),$(OBJS-y) $(OBJS-n) $(OBJS-))

DEPS-y := $(call src2dep,$(SRCS-y))
DEPS-n := $(call src2dep,$(SRCS-n))
DEPS-  := $(call src2dep,$(SRCS-))
DEPS-all := $(DEPS-y) $(DEPS-n) $(DEPS-)
DEPSTMP-all := $(DEPS-all:%.d=%.d.tmp)

CMDS-y := $(call src2cmd,$(SRCS-y))
CMDS-n := $(call src2cmd,$(SRCS-n))
CMDS-  := $(call src2cmd,$(SRCS-))
CMDS-all := $(CMDS-y) $(CMDS-n) $(CMDS-)

-include $(DEPS-y) $(CMDS-y)

# command to compile a .cpp file to generate an object
ifeq ($(USE_HOST),1)
CXX_TO_O = $(HOSTCXX) -Wp,-MD,$(call obj2dep,$(@)).tmp $(HOST_CXXFLAGS) \
	$(CXXFLAGS_$(@)) $(HOST_EXTRA_CXXFLAGS) -o $@ -c $<
CXX_TO_O_STR = $(subst ','\'',$(CXX_TO_O)) #'# fix syntax highlight
CXX_TO_O_DISP = $(if $(V),"$(CXX_TO_O_STR)","  HOSTCXX $(@)")
else
CXX_TO_O = $(CXX) -Wp,-MD,$(call obj2dep,$(@)).tmp $(CXXFLAGS) \
	$(CXXFLAGS_$(@)) $(EXTRA_CXXFLAGS) -o $@ -c $<
CXX_TO_O_STR = $(subst ','\'',$(CXX_TO_O)) #'# fix syntax highlight
CXX_TO_O_DISP = $(if $(V),"$(CXX_TO_O_STR)","  CXX $(@)")
endif
CXX_TO_O_CMD = 'cmd_$@ = $(CXX_TO_O_STR)'
CXX_TO_O_DO = @set -e; \
	echo $(CXX_TO_O_DISP); \
	$(CXX_TO_O) && \
	echo $(CXX_TO_O_CMD) > $(call obj2cmd,$(@)) && \
	sed 's,'$@':,dep_'$@' =,' $(call obj2dep,$(@)).tmp > $(call obj2dep,$(@)) && \
	rm -f $(call obj2dep,$(@)).tmp

#
# Compile .cpp file if needed
# Note: dep_$$@ is from the .d file and DEP_$$@ can be specified by
# user (by default it is empty)
#
#.SECONDEXPANSION:
%_cpp.o: %.cpp $$(wildcard $$(dep_$$@)) $$(DEP_$$(@)) FORCE
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	$(if $(D),\
		@echo -n "$< -> $@ " ; \
		echo -n "file_missing=$(call boolean,$(file_missing)) " ; \
		echo -n "cmdline_changed=$(call boolean,$(call cmdline_changed,$(CXX_TO_O))) " ; \
		echo -n "depfile_missing=$(call boolean,$(depfile_missing)) " ; \
		echo "depfile_newer=$(call boolean,$(depfile_newer))")
	$(if $(or \
		$(file_missing),\
		$(call cmdline_changed,$(CXX_TO_O)),\
		$(depfile_missing),\
		$(depfile_newer)),\
		$(CXX_TO_O_DO))

