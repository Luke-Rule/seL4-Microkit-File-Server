
#pragma once

#include <stdint.h>

#include "fs_internal.h"

file_descriptor_result_t get_file_descriptor(fs_state_t *state, const uint8_t client_id, const size_t file_id);

file_id_and_cursor_result_t add_i_node_to_fd_table(fs_state_t *state, const uint8_t client_id,
													const uint32_t i_node_index,
													const file_open_operations_t requested_operations);

fs_result_t close_file_by_i_node_index(fs_state_t *state, const uint8_t client_id, const uint32_t i_node_index);

bool is_i_node_open(fs_state_t *state, const uint32_t i_node_index);
bool is_i_node_open_by_other_client(fs_state_t *state, const uint32_t i_node_index, const uint8_t caller);
bool is_i_node_open_by_client(fs_state_t *state, const uint32_t i_node_index, const uint8_t client_id);