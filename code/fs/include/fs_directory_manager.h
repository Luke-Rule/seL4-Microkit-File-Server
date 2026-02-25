
#pragma once

#include <stdint.h>

#include "fs_internal.h"
#include "fs_shared.h"

child_slot_and_block_result_t get_free_child_slot(uint32_t parent_i_node_index);

i_node_result_t add_entry(uint32_t parent_i_node_index, unsigned char *name, permissions_t permissions,
						  uint8_t client_id, uint32_t block_index, uint32_t entry_index,
						  int is_directory);

fs_result_t delete_directory_contents(uint32_t i_node_index);

void defragment_directory(i_node_t *parent_i_node);
