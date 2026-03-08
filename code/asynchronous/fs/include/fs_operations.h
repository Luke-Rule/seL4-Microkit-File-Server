
#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "fs_internal.h"
#include "fs_shared.h"

i_node_result_t create_entry(unsigned char *path, const uint32_t parent_i_node_index,
                             const permissions_t permissions, const uint8_t client_id, const bool is_directory);

void delete_entry_operation(const uint8_t client_id, unsigned char *path);
void set_entry_permissions_operation(const uint8_t client_id, permissions_t permissions, unsigned char *path);
void get_entry_permissions_operation(const uint8_t client_id, unsigned char *path);
void get_entry_size_operation(const uint8_t client_id, unsigned char *path);
void entry_exists_operation(const uint8_t client_id, unsigned char *path);
void list_directory_operation(const uint8_t client_id, unsigned char *path);

void open_file_operation(const uint8_t client_id, const file_open_operations_t requested_operations, unsigned char *path);
void close_file_operation(const uint8_t client_id, const uint32_t file_descriptor_index);
void read_file_operation(const uint8_t client_id, const uint32_t file_descriptor_index, const size_t length);
void write_file_operation(const uint8_t client_id, const uint32_t file_descriptor_index, const size_t length,
                          const size_t submission_buffer_index);
void seek_file_operation(const uint8_t client_id, const uint32_t file_descriptor_index, const size_t position);
