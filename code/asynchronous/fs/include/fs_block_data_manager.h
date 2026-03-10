
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "fs_internal.h"
#include "fs_shared.h"

block_search_result_t get_inode_block_index_from_file_cursor_position(const size_t file_cursor_position);

fs_result_t copy_bytes_i_node(fs_state_t *state, i_node_t *i_node, uint8_t *client_buffer, size_t length,
							  file_descriptor_t *fd, const bool rnw);
