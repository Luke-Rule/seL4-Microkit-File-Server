
#pragma once

#include <stdint.h>

#include "fs_internal.h"
#include "fs_shared.h"

file_descriptor_result_t get_file_descriptor(uint32_t client_id, uint32_t file_index);

file_index_and_cursor_result_t add_i_node_to_fd_table(uint32_t client_id, uint32_t i_node_index,
													  uint8_t requested_operations);

fs_result_t close_file_by_i_node_index(uint32_t client_id, uint32_t i_node_index);
uint8_t is_i_node_open(uint32_t i_node_index);