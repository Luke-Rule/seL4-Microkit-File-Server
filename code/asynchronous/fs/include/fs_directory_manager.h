
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "fs_internal.h"
#include "fs_shared.h"

child_slot_and_block_result_t get_free_child_slot(const uint32_t parent_i_node_index);

i_node_result_t add_entry(const uint32_t parent_i_node_index, const unsigned char *name, const permissions_t permissions,
						  const uint8_t client_id, const size_t block_index, const size_t entry_index,
						  const bool is_directory);

fs_result_t delete_directory_contents(uint32_t i_node_index);

void defragment_directory(i_node_t *parent_i_node);
