CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -Wno-old-style-declaration -Wno-sign-compare -Wno-enum-conversion -O0 -g
CPPFLAGS := -I. -Iinclude -I.. -I../include

BUILD_DIR := build
TARGET := $(BUILD_DIR)/fs_unit_tests

TEST_SRCS := \
	unit_test_utils.c \
	util_tests.c \
	block_tests.c \
	i_node_tests.c \
	file_descriptor_tests.c

LIB_SRCS := \
	../fs_utils.c \
	../fs_block_manager.c \
	../fs_i_node_manager.c \
	../fs_file_table_manager.c

OBJS := \
	$(BUILD_DIR)/unit_test_utils.o \
	$(BUILD_DIR)/util_tests.o \
	$(BUILD_DIR)/block_tests.o \
	$(BUILD_DIR)/i_node_tests.o \
	$(BUILD_DIR)/file_descriptor_tests.o \
	$(BUILD_DIR)/fs_utils.o \
	$(BUILD_DIR)/fs_block_manager.o \
	$(BUILD_DIR)/fs_i_node_manager.o \
	$(BUILD_DIR)/fs_file_table_manager.o

.PHONY: all run clean

all: $(TARGET)

run: $(TARGET)
	./$(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/unit_test_utils.o: unit_test_utils.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/util_tests.o: util_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/block_tests.o: block_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/i_node_tests.o: i_node_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/file_descriptor_tests.o: file_descriptor_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/fs_utils.o: ../fs_utils.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/fs_block_manager.o: ../fs_block_manager.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/fs_i_node_manager.o: ../fs_i_node_manager.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/fs_file_table_manager.o: ../fs_file_table_manager.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf $(BUILD_DIR)