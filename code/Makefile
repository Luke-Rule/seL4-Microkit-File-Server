# Environment
MICROKIT_SDK := ../microkit-sdk-2.0.1
TOOLCHAIN := aarch64-linux-gnu

BOARD := qemu_virt_aarch64
MICROKIT_CONFIG := debug
BUILD_DIR := build

CPU := cortex-a53

CC := $(TOOLCHAIN)-gcc
LD := $(TOOLCHAIN)-ld
AS := $(TOOLCHAIN)-as
MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit

# Source files and objects
CLIENT_OBJS := client.o
TESTS_OBJS := fs_tests.o
FILESERVER_OBJS := file_server.o
FILESERVER_DYNAMIC_OBJS := file_dynamic_server.o

BOARD_DIR := $(MICROKIT_SDK)/board/$(BOARD)/$(MICROKIT_CONFIG)

# Compiler and linker flags
CFLAGS := -mcpu=$(CPU) -mstrict-align -nostdlib -ffreestanding -g -Werror -I$(BOARD_DIR)/include -Ivmm/src/util -Iinclude -DBOARD_$(BOARD)
LDFLAGS := -L$(BOARD_DIR)/lib
LIBS := -lmicrokit -Tmicrokit.ld

# Output files
CLIENT_ELF := $(BUILD_DIR)/client.elf
TESTS_ELF := $(BUILD_DIR)/fs_tests.elf
FILESERVER_ELF := $(BUILD_DIR)/file_server.elf
FILESERVER_DYNAMIC_ELF := $(BUILD_DIR)/file_dynamic_server.elf
IMAGE_FILE = $(BUILD_DIR)/loader.img
TEST_IMAGE_FILE = $(BUILD_DIR)/fs_tests_loader.img
REPORT_FILE = $(BUILD_DIR)/report.txt
SYSTEM_FILE := file.system
TEST_SYSTEM_FILE := fs_tests.system

# Targets
all: directories $(IMAGE_FILE) $(TEST_IMAGE_FILE)
directories:
	$(info $(shell mkdir -p $(BUILD_DIR)))
	
# Compile .c -> .o and generate dependency file
$(BUILD_DIR)/%.o: %.c Makefile
	$(CC) -c $(CFLAGS) -MMD -MP $< -o $@

# Include dependency files if they exist
-include $(BUILD_DIR)/*.d

# Link each component ELF including utilities
$(CLIENT_ELF): $(addprefix $(BUILD_DIR)/, $(CLIENT_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(TESTS_ELF): $(addprefix $(BUILD_DIR)/, $(TESTS_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(FILESERVER_ELF): $(addprefix $(BUILD_DIR)/, $(FILESERVER_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(FILESERVER_DYNAMIC_ELF): $(addprefix $(BUILD_DIR)/, $(FILESERVER_DYNAMIC_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

# Build Microkit image
$(IMAGE_FILE): $(CLIENT_ELF) $(FILESERVER_ELF) $(SYSTEM_FILE)
	$(MICROKIT_TOOL) $(SYSTEM_FILE) --search-path $(BUILD_DIR) \
		--board $(BOARD) --config $(MICROKIT_CONFIG) \
		-o $(IMAGE_FILE) -r $(REPORT_FILE)

$(TEST_IMAGE_FILE): $(TESTS_ELF) $(FILESERVER_DYNAMIC_ELF) $(TEST_SYSTEM_FILE)
	$(MICROKIT_TOOL) $(TEST_SYSTEM_FILE) --search-path $(BUILD_DIR) \
		--board $(BOARD) --config $(MICROKIT_CONFIG) \
		-o $(TEST_IMAGE_FILE) -r $(REPORT_FILE)

# Run in QEMU
run: $(IMAGE_FILE)
	qemu-system-aarch64 -machine virt,virtualization=on \
		-cpu $(CPU) \
		-serial mon:stdio \
		-device loader,file=$(IMAGE_FILE),addr=0x70000000,cpu-num=0 \
		-m size=2G \
		-nographic \
		-netdev user,id=mynet0 \
		-device virtio-net-device,netdev=mynet0,mac=52:55:00:d1:55:01

test: $(TEST_IMAGE_FILE)
	qemu-system-aarch64 -machine virt,virtualization=on \
		-cpu $(CPU) \
		-serial mon:stdio \
		-device loader,file=$(TEST_IMAGE_FILE),addr=0x70000000,cpu-num=0 \
		-m size=2G \
		-nographic \
		-netdev user,id=mynet0 \
		-device virtio-net-device,netdev=mynet0,mac=52:55:00:d1:55:01

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)