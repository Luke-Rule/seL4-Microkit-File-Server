
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "fs_internal.h"
#include "fs_shared.h"

i_node_result_t create_entry(unsigned char *path, uint32_t parent_i_node_index,
                             permissions_t permissions, uint8_t client_id, int is_directory);

void delete_entry_operation(uint32_t client_id, unsigned char *path);
void set_entry_permissions_operation(uint32_t client_id, permissions_t permissions, unsigned char *path);
void get_entry_permissions_operation(uint32_t client_id, unsigned char *path);
void get_entry_size_operation(uint32_t client_id, unsigned char *path);
void entry_exists_operation(uint32_t client_id, unsigned char *path);
void list_directory_operation(uint32_t client_id, unsigned char *path);

void open_file_operation(uint32_t client_id, uint8_t requested_operations, char *path);
void close_file_operation(uint32_t client_id, uint32_t file_descriptor_index);
void read_file_operation(uint32_t client_id, uint32_t file_descriptor_index, size_t length);
void write_file_operation(uint32_t client_id, uint32_t file_descriptor_index, size_t length,
                          int submission_buffer_index);
void seek_file_operation(uint32_t client_id, uint32_t file_descriptor_index, uint32_t position);
