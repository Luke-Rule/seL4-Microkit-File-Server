
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "fs_internal.h"
#include "fs_shared.h"

block_search_result_t get_inode_block_index_from_file_index(uint32_t file_index);

fs_result_t copy_bytes_i_node(i_node_t *i_node, uint8_t *client_buffer, size_t length,
							  file_descriptor_t *fd, int rnw);
