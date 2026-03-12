# Environment
MICROKIT_SDK ?= ../../microkit-sdk-2.0.1
TOOLCHAIN := aarch64-linux-gnu
NUM_CLIENTS ?= 3

VALID_MULTI_CLIENT_COUNTS := 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
ALL_MULTI_CLIENT_INDEXES := 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
BENCHMARK_MULTI_ALIASES := 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16

ifeq ($(filter $(NUM_CLIENTS),$(VALID_MULTI_CLIENT_COUNTS)),)
$(error NUM_CLIENTS must be one of: $(VALID_MULTI_CLIENT_COUNTS))
endif

ACTIVE_MULTI_CLIENT_INDEXES := $(wordlist 1,$(NUM_CLIENTS),$(ALL_MULTI_CLIENT_INDEXES))

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
VPATH := fs:tests:tests/single_client:tests/multi_client:benchmarks:benchmarks/clients:../shared_fs:../shared_test

MOVED_SHARED_DEPS := $(addprefix $(BUILD_DIR)/, \
	fs_block_data_manager.d \
	fs_block_manager.d \
	fs_directory_manager.d \
	fs_file_table_manager.d \
	fs_i_node_manager.d \
	fs_utils.d)

MOVED_BENCHMARK_CLIENT_DEPS := $(BUILD_DIR)/single_client.d $(foreach idx,$(ALL_MULTI_CLIENT_INDEXES),$(BUILD_DIR)/multi_client_$(idx).d)
MOVED_TEST_DEPS := $(BUILD_DIR)/fs_tests.d $(BUILD_DIR)/test_utils.d $(BUILD_DIR)/test_common.d $(BUILD_DIR)/client_0.d $(BUILD_DIR)/client_1.d $(BUILD_DIR)/client_2.d

$(shell rm -f $(MOVED_SHARED_DEPS) $(MOVED_BENCHMARK_CLIENT_DEPS) $(MOVED_TEST_DEPS))

SINGLE_TEST_OBJS := fs_tests.o test_utils.o test_common.o fs_api.o fs_utils.o $(COMMON_OBJS)
MULTI_CLIENT_COMMON_OBJS := test_utils.o test_common.o fs_api.o fs_utils.o $(COMMON_OBJS)
MULTI_CLIENT0_OBJ := client_0.o
MULTI_CLIENT1_OBJ := client_1.o
MULTI_CLIENT2_OBJ := client_2.o

FILESERVER_OBJS := file_server_benchmark.o \
	fs_operations.o \
	fs_directory_manager.o \
	fs_i_node_manager.o \
	fs_file_table_manager.o \
	fs_block_manager.o \
	fs_block_data_manager.o \
	fs_utils.o

FILESERVER_MULTI_BENCHMARK_OBJ := file_server_multi_benchmark_$(NUM_CLIENTS).o

FILESERVER_MULTI_OBJS := $(FILESERVER_MULTI_BENCHMARK_OBJ) \
	fs_operations.o \
	fs_directory_manager.o \
	fs_i_node_manager.o \
	fs_file_table_manager.o \
	fs_block_manager.o \
	fs_block_data_manager.o \
	fs_utils.o

FILESERVER_TEST_OBJS := file_server_test.o \
	fs_operations.o \
	fs_directory_manager.o \
	fs_i_node_manager.o \
	fs_file_table_manager.o \
	fs_block_manager.o \
	fs_block_data_manager.o \
	fs_utils.o

FILESERVER_MULTI_TEST_OBJS := file_server_multi_test.o \
	fs_operations.o \
	fs_directory_manager.o \
	fs_i_node_manager.o \
	fs_file_table_manager.o \
	fs_block_manager.o \
	fs_block_data_manager.o \
	fs_utils.o

BENCHMARK_COMMON_OBJS := benchmark_utils.o benchmark_shared.o fs_api.o fs_utils.o
SINGLE_BENCHMARK_OBJS := single_client.o $(BENCHMARK_COMMON_OBJS)
MULTI_BENCHMARK_ELFS := $(foreach idx,$(ACTIVE_MULTI_CLIENT_INDEXES),$(BUILD_DIR)/multi_client_$(idx).elf)

PER_OP_BENCHMARK_COMMON_OBJS := per_op_benchmark_utils.o benchmark_shared.o fs_api.o fs_utils.o
PER_OP_SINGLE_BENCHMARK_OBJS := per_op_single_client.o $(PER_OP_BENCHMARK_COMMON_OBJS)

BOARD_DIR := $(MICROKIT_SDK)/board/$(BOARD)/$(MICROKIT_CONFIG)

# Compiler and linker flags
CFLAGS := -mcpu=$(CPU) -mstrict-align -nostdlib -ffreestanding -g -Werror $(OPT) -I$(BOARD_DIR)/include -Ivmm/src/util -DBOARD_$(BOARD) -I. -I.. -I../shared_test -Ifs -Ifs/include -Itests/include -Ibenchmarks -I../shared_fs/include
LDFLAGS := -L$(BOARD_DIR)/lib
LIBS := -lmicrokit -Tmicrokit.ld

# Output files
SINGLE_TEST_ELF := $(BUILD_DIR)/fs_tests.elf
SINGLE_BENCHMARK_ELF := $(BUILD_DIR)/single_client.elf
PER_OP_SINGLE_BENCHMARK_ELF := $(BUILD_DIR)/per_op_single_client.elf

MULTI_TEST_CLIENT0_ELF := $(BUILD_DIR)/multi_test_client_0.elf
MULTI_TEST_CLIENT1_ELF := $(BUILD_DIR)/multi_test_client_1.elf
MULTI_TEST_CLIENT2_ELF := $(BUILD_DIR)/multi_test_client_2.elf

FILESERVER_ELF := $(BUILD_DIR)/file_server.elf
FILESERVER_MULTI_ELF := $(BUILD_DIR)/file_server_multi.elf
FILESERVER_TEST_ELF := $(BUILD_DIR)/file_server_test.elf
FILESERVER_MULTI_TEST_ELF := $(BUILD_DIR)/file_server_multi_test.elf
SINGLE_TEST_IMAGE := $(BUILD_DIR)/single_test_loader.img
MULTI_TEST_IMAGE := $(BUILD_DIR)/multi_test_loader.img
SINGLE_BENCHMARK_IMAGE := $(BUILD_DIR)/benchmark_1_loader.img
MULTI_BENCHMARK_IMAGE := $(BUILD_DIR)/benchmark_$(NUM_CLIENTS)_loader.img
PER_OP_BENCHMARK_IMAGE := $(BUILD_DIR)/per_op_benchmark_1_loader.img
TEST_REPORT_FILE := $(BUILD_DIR)/report.txt
SINGLE_REPORT_FILE := $(BUILD_DIR)/benchmark_1_report.txt
MULTI_REPORT_FILE := $(BUILD_DIR)/benchmark_$(NUM_CLIENTS)_report.txt
SINGLE_TEST_SYSTEM := tests/single_client/single_client_test.system
MULTI_TEST_SYSTEM := tests/multi_client/multi_client_test.system
SINGLE_BENCHMARK_SYSTEM := benchmarks/systems/1.system
MULTI_BENCHMARK_SYSTEM := benchmarks/systems/$(NUM_CLIENTS).system
PER_OP_BENCHMARK_SYSTEM := benchmarks/systems/per_op_1.system

# Targets
all: directories $(SINGLE_TEST_IMAGE)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

directories: $(BUILD_DIR)
	
# Compile .c -> .o and generate dependency file
$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -MMD -MP $< -o $@

$(BUILD_DIR)/single_client.o: benchmarks/clients/single_client.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -MMD -MP $< -o $@

$(BUILD_DIR)/per_op_single_client.o: benchmarks/clients/per_op_single_client.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -MMD -MP $< -o $@

$(BUILD_DIR)/multi_client_%.o: benchmarks/clients/multi_client_%.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -MMD -MP $< -o $@

# Include dependency files if they exist
-include $(BUILD_DIR)/*.d

# Link each component ELF including utilities
$(SINGLE_TEST_ELF): $(addprefix $(BUILD_DIR)/, $(SINGLE_TEST_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(SINGLE_BENCHMARK_ELF): $(addprefix $(BUILD_DIR)/, $(SINGLE_BENCHMARK_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(PER_OP_SINGLE_BENCHMARK_ELF): $(addprefix $(BUILD_DIR)/, $(PER_OP_SINGLE_BENCHMARK_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(MULTI_TEST_CLIENT0_ELF): $(addprefix $(BUILD_DIR)/, $(MULTI_CLIENT0_OBJ) $(MULTI_CLIENT_COMMON_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(MULTI_TEST_CLIENT1_ELF): $(addprefix $(BUILD_DIR)/, $(MULTI_CLIENT1_OBJ) $(MULTI_CLIENT_COMMON_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(MULTI_TEST_CLIENT2_ELF): $(addprefix $(BUILD_DIR)/, $(MULTI_CLIENT2_OBJ) $(MULTI_CLIENT_COMMON_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(BUILD_DIR)/multi_client_%.elf: $(addprefix $(BUILD_DIR)/, multi_client_%.o $(BENCHMARK_COMMON_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(FILESERVER_ELF): $(addprefix $(BUILD_DIR)/, $(FILESERVER_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(FILESERVER_MULTI_ELF): $(addprefix $(BUILD_DIR)/, $(FILESERVER_MULTI_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(FILESERVER_TEST_ELF): $(addprefix $(BUILD_DIR)/, $(FILESERVER_TEST_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(FILESERVER_MULTI_TEST_ELF): $(addprefix $(BUILD_DIR)/, $(FILESERVER_MULTI_TEST_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(SINGLE_TEST_IMAGE): $(SINGLE_TEST_ELF) $(FILESERVER_TEST_ELF) $(SINGLE_TEST_SYSTEM)
	$(MICROKIT_TOOL) $(SINGLE_TEST_SYSTEM) --search-path $(BUILD_DIR) \
		--board $(BOARD) --config $(MICROKIT_CONFIG) \
		-o $(SINGLE_TEST_IMAGE) -r $(TEST_REPORT_FILE)

$(MULTI_TEST_IMAGE): $(MULTI_TEST_CLIENT0_ELF) $(MULTI_TEST_CLIENT1_ELF) $(MULTI_TEST_CLIENT2_ELF) $(FILESERVER_MULTI_TEST_ELF) $(MULTI_TEST_SYSTEM)
	$(MICROKIT_TOOL) $(MULTI_TEST_SYSTEM) --search-path $(BUILD_DIR) \
		--board $(BOARD) --config $(MICROKIT_CONFIG) \
		-o $(MULTI_TEST_IMAGE) -r $(TEST_REPORT_FILE)

$(SINGLE_BENCHMARK_IMAGE): $(SINGLE_BENCHMARK_ELF) $(FILESERVER_ELF) $(SINGLE_BENCHMARK_SYSTEM)
	$(MICROKIT_TOOL) $(SINGLE_BENCHMARK_SYSTEM) --search-path $(BUILD_DIR) \
		--board $(BOARD) --config $(MICROKIT_CONFIG) \
		-o $(SINGLE_BENCHMARK_IMAGE) -r $(SINGLE_REPORT_FILE)

$(MULTI_BENCHMARK_IMAGE): $(MULTI_BENCHMARK_ELFS) $(FILESERVER_MULTI_ELF) $(MULTI_BENCHMARK_SYSTEM)
	$(MICROKIT_TOOL) $(MULTI_BENCHMARK_SYSTEM) --search-path $(BUILD_DIR) \
		--board $(BOARD) --config $(MICROKIT_CONFIG) \
		-o $(MULTI_BENCHMARK_IMAGE) -r $(MULTI_REPORT_FILE)

$(PER_OP_BENCHMARK_IMAGE): $(PER_OP_SINGLE_BENCHMARK_ELF) $(FILESERVER_ELF) $(PER_OP_BENCHMARK_SYSTEM)
	$(MICROKIT_TOOL) $(PER_OP_BENCHMARK_SYSTEM) --search-path $(BUILD_DIR) \
		--board $(BOARD) --config $(MICROKIT_CONFIG) \
		-o $(PER_OP_BENCHMARK_IMAGE) -r $(SINGLE_REPORT_FILE)

$(BUILD_DIR)/file_server_benchmark.o: fs/file_server.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -DBENCHMARKING=1 -MMD -MP $< -o $@

$(BUILD_DIR)/$(FILESERVER_MULTI_BENCHMARK_OBJ): fs/file_server.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -DNUMBER_OF_CLIENTS=$(NUM_CLIENTS) -DBENCHMARKING=1 -MMD -MP $< -o $@

$(BUILD_DIR)/file_server_test.o: fs/file_server.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -DBENCHMARKING=0 -MMD -MP $< -o $@

$(BUILD_DIR)/file_server_multi_test.o: fs/file_server.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -DNUMBER_OF_CLIENTS=3 -DBENCHMARKING=0 -MMD -MP $< -o $@

single_test: $(SINGLE_TEST_IMAGE)
	qemu-system-aarch64 -machine virt,virtualization=on \
		-cpu $(CPU) \
		-serial mon:stdio \
		-device loader,file=$(SINGLE_TEST_IMAGE),addr=0x70000000,cpu-num=0 \
		-m size=2G \
		-nographic \
		-netdev user,id=mynet0 \
		-device virtio-net-device,netdev=mynet0,mac=52:55:00:d1:55:01

multi_test: $(MULTI_TEST_IMAGE)
	qemu-system-aarch64 -machine virt,virtualization=on \
		-cpu $(CPU) \
		-serial mon:stdio \
		-device loader,file=$(MULTI_TEST_IMAGE),addr=0x70000000,cpu-num=0 \
		-m size=2G \
		-nographic \
		-netdev user,id=mynet0 \
		-device virtio-net-device,netdev=mynet0,mac=52:55:00:d1:55:01

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

benchmark_multi: $(MULTI_BENCHMARK_IMAGE)

benchmark_1: $(SINGLE_BENCHMARK_IMAGE)

benchmark_3: $(MULTI_BENCHMARK_IMAGE)

per_op_benchmark: $(PER_OP_BENCHMARK_IMAGE)
	qemu-system-aarch64 -machine virt,virtualization=on \
		-cpu $(CPU) \
		-serial mon:stdio \
		-device loader,file=$(PER_OP_BENCHMARK_IMAGE),addr=0x70000000,cpu-num=0 \
		-m size=2G \
		-nographic \
		-netdev user,id=mynet0 \
		-device virtio-net-device,netdev=mynet0,mac=52:55:00:d1:55:01

generate_benchmark_systems:
	/usr/bin/python3 benchmarks/generate_benchmark_multi_systems.py

test: single_test

.PHONY: all single_test multi_test benchmark_1 benchmark_3 benchmark_multi $(addprefix benchmark_,$(BENCHMARK_MULTI_ALIASES)) single_benchmark multi_benchmark per_op_benchmark generate_benchmark_systems clean test

$(foreach count,$(BENCHMARK_MULTI_ALIASES),$(eval benchmark_$(count): ; @$(MAKE) benchmark_multi NUM_CLIENTS=$(count)))

$(BUILD_DIR)/client_0.o: tests/multi_client/client_0.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -MMD -MP $< -o $@

$(BUILD_DIR)/client_1.o: tests/multi_client/client_1.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -MMD -MP $< -o $@

$(BUILD_DIR)/client_2.o: tests/multi_client/client_2.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -MMD -MP $< -o $@

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)