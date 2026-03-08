# Environment
MICROKIT_SDK := ../microkit-sdk-2.0.1
TOOLCHAIN := aarch64-linux-gnu

BOARD := qemu_virt_aarch64
MICROKIT_CONFIG := debug
BUILD_DIR := build

CPU := cortex-a53

OPT ?= -O2

CC := $(TOOLCHAIN)-gcc
LD := $(TOOLCHAIN)-ld
AS := $(TOOLCHAIN)-as
MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit

# VPATH to find sources in subdirectories
VPATH := fs:benchmarks

FILESERVER_OBJS := file_server_benchmark.o \
	fs_operations.o \
	fs_directory_manager.o \
	fs_i_node_manager.o \
	fs_file_table_manager.o \
	fs_block_manager.o \
	fs_block_data_manager.o \
	fs_utils.o

FILESERVER_MULTI_OBJS := file_server_multi_benchmark.o \
	fs_operations.o \
	fs_directory_manager.o \
	fs_i_node_manager.o \
	fs_file_table_manager.o \
	fs_block_manager.o \
	fs_block_data_manager.o \
	fs_utils.o

BENCHMARK_COMMON_OBJS := benchmark_utils.o fs_api.o
SINGLE_BENCHMARK_OBJS := single_client.o $(BENCHMARK_COMMON_OBJS)
MULTI_CLIENT0_OBJS := multi_client_0.o $(BENCHMARK_COMMON_OBJS)
MULTI_CLIENT1_OBJS := multi_client_1.o $(BENCHMARK_COMMON_OBJS)
MULTI_CLIENT2_OBJS := multi_client_2.o $(BENCHMARK_COMMON_OBJS)

BOARD_DIR := $(MICROKIT_SDK)/board/$(BOARD)/$(MICROKIT_CONFIG)

# Compiler and linker flags
CFLAGS := -mcpu=$(CPU) -mstrict-align -nostdlib -ffreestanding -g -Werror $(OPT) -I$(BOARD_DIR)/include -Ivmm/src/util -DBOARD_$(BOARD) -I. -Ifs/include -Ibenchmarks
LDFLAGS := -L$(BOARD_DIR)/lib
LIBS := -lmicrokit -Tmicrokit.ld

# Output files
SINGLE_BENCHMARK_ELF := $(BUILD_DIR)/single_client.elf

MULTI_CLIENT0_ELF := $(BUILD_DIR)/multi_client_0.elf
MULTI_CLIENT1_ELF := $(BUILD_DIR)/multi_client_1.elf
MULTI_CLIENT2_ELF := $(BUILD_DIR)/multi_client_2.elf
FILESERVER_ELF := $(BUILD_DIR)/file_server.elf
FILESERVER_MULTI_ELF := $(BUILD_DIR)/file_server_multi.elf
SINGLE_BENCHMARK_IMAGE := $(BUILD_DIR)/benchmark_1_loader.img
MULTI_BENCHMARK_IMAGE := $(BUILD_DIR)/benchmark_3_loader.img
SINGLE_REPORT_FILE := $(BUILD_DIR)/benchmark_1_report.txt
MULTI_REPORT_FILE := $(BUILD_DIR)/benchmark_3_report.txt
SINGLE_BENCHMARK_SYSTEM := benchmarks/1.system
MULTI_BENCHMARK_SYSTEM := benchmarks/3.system

# Targets
all: $(SINGLE_BENCHMARK_IMAGE)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

directories: $(BUILD_DIR)
	
# Compile .c -> .o and generate dependency file
$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -MMD -MP $< -o $@

# Include dependency files if they exist
-include $(BUILD_DIR)/*.d

# Link each component ELF including utilities
$(SINGLE_BENCHMARK_ELF): $(addprefix $(BUILD_DIR)/, $(SINGLE_BENCHMARK_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(MULTI_CLIENT0_ELF): $(addprefix $(BUILD_DIR)/, $(MULTI_CLIENT0_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(MULTI_CLIENT1_ELF): $(addprefix $(BUILD_DIR)/, $(MULTI_CLIENT1_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(MULTI_CLIENT2_ELF): $(addprefix $(BUILD_DIR)/, $(MULTI_CLIENT2_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(FILESERVER_ELF): $(addprefix $(BUILD_DIR)/, $(FILESERVER_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(FILESERVER_MULTI_ELF): $(addprefix $(BUILD_DIR)/, $(FILESERVER_MULTI_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(SINGLE_BENCHMARK_IMAGE): $(SINGLE_BENCHMARK_ELF) $(FILESERVER_ELF) $(SINGLE_BENCHMARK_SYSTEM)
	$(MICROKIT_TOOL) $(SINGLE_BENCHMARK_SYSTEM) --search-path $(BUILD_DIR) \
		--board $(BOARD) --config $(MICROKIT_CONFIG) \
		-o $(SINGLE_BENCHMARK_IMAGE) -r $(SINGLE_REPORT_FILE)

$(MULTI_BENCHMARK_IMAGE): $(MULTI_CLIENT0_ELF) $(MULTI_CLIENT1_ELF) $(MULTI_CLIENT2_ELF) $(FILESERVER_MULTI_ELF) $(MULTI_BENCHMARK_SYSTEM)
	$(MICROKIT_TOOL) $(MULTI_BENCHMARK_SYSTEM) --search-path $(BUILD_DIR) \
		--board $(BOARD) --config $(MICROKIT_CONFIG) \
		-o $(MULTI_BENCHMARK_IMAGE) -r $(MULTI_REPORT_FILE)

$(BUILD_DIR)/file_server_benchmark.o: fs/file_server.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -DBENCHMARKING=1 -MMD -MP $< -o $@

$(BUILD_DIR)/file_server_multi_benchmark.o: fs/file_server.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -DNUMBER_OF_CLIENTS=3 -DBENCHMARKING=1 -MMD -MP $< -o $@

single_benchmark: $(SINGLE_BENCHMARK_IMAGE)
	qemu-system-aarch64 -machine virt,virtualization=on \
		-cpu $(CPU) \
		-serial mon:stdio \
		-device loader,file=$(SINGLE_BENCHMARK_IMAGE),addr=0x70000000,cpu-num=0 \
		-m size=2G \
		-nographic \
		-netdev user,id=mynet0 \
		-device virtio-net-device,netdev=mynet0,mac=52:55:00:d1:55:01

multi_benchmark: $(MULTI_BENCHMARK_IMAGE)
	qemu-system-aarch64 -machine virt,virtualization=on \
		-cpu $(CPU) \
		-serial mon:stdio \
		-device loader,file=$(MULTI_BENCHMARK_IMAGE),addr=0x70000000,cpu-num=0 \
		-m size=2G \
		-nographic \
		-netdev user,id=mynet0 \
		-device virtio-net-device,netdev=mynet0,mac=52:55:00:d1:55:01

benchmark_1: $(SINGLE_BENCHMARK_IMAGE)

benchmark_3: $(MULTI_BENCHMARK_IMAGE)

test: single_benchmark

.PHONY: all benchmark_1 benchmark_3 single_benchmark multi_benchmark clean test

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)