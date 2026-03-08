
#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "fs_internal.h"
#include "fs_shared.h"

i_node_result_t create_entry(unsigned char *path, const uint32_t parent_i_node_index,
                             const permissions_t permissions, const uint8_t client_id, const bool is_directory);

fs_result_t delete_entry_operation(uint32_t client_id, unsigned char *path);
fs_result_t set_entry_permissions_operation(uint32_t client_id, permissions_t permissions, unsigned char *path);
fs_result_t get_entry_permissions_operation(uint32_t client_id, unsigned char *path);
fs_result_t get_entry_size_operation(uint32_t client_id, unsigned char *path);
fs_result_t entry_exists_operation(uint32_t client_id, unsigned char *path);
fs_result_t list_directory_operation(uint32_t client_id, unsigned char *path);

fs_result_t open_file_operation(uint32_t client_id, file_open_operations_t requested_operations, char *path);
fs_result_t close_file_operation(uint32_t client_id, uint32_t file_descriptor_index);
fs_result_t read_file_operation(uint32_t client_id, uint32_t file_descriptor_index, size_t length);
fs_result_t write_file_operation(uint32_t client_id, uint32_t file_descriptor_index, size_t length);
fs_result_t seek_file_operation(uint32_t client_id, uint32_t file_descriptor_index, size_t position);
