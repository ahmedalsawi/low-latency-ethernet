SIM ?= verilator
TOPLEVEL_LANG ?= verilog

TOPLEVEL ?= eth_tx
MODULE ?= test_eth_tx

# Compile options
FILELIST ?= compile.f

ifneq ($(wildcard $(FILELIST)),)
FILELIST_ABS := $(abspath $(FILELIST))
FILELIST_DIR := $(dir $(FILELIST_ABS))
VERILOG_SOURCES := $(addprefix $(FILELIST_DIR),$(shell sed -e 's/#.*//' -e '/^[[:space:]]*$$/d' $(FILELIST_ABS)))
else
$(error File list $(FILELIST) not found)
endif

# PARAM_DATA_W ?= 64
# PARAM_FIFO_D ?= 16

# COMPILE_ARGS += -GDATA_W=$(PARAM_DATA_W)
# COMPILE_ARGS += -GFIFO_D=$(PARAM_FIFO_D)

COMPILE_ARGS += -Wall -Wpedantic -Wno-GENUNNAMED -Wno-LATCH -Wno-IMPLICIT
COMPILE_ARGS += -Wno-UNUSEDPARAM -Wno-DECLFILENAME

WAVES ?= 1
EXTRA_ARGS += --trace --trace-structs

include $(shell cocotb-config --makefiles)/Makefile.sim
