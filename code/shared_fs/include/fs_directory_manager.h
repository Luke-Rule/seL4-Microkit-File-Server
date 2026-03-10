
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "fs_internal.h"

child_slot_and_block_result_t get_free_child_slot(fs_state_t *state, const uint32_t parent_i_node_index);

fs_result_t delete_directory_contents(fs_state_t *state, uint32_t i_node_index);

void defragment_directory(fs_state_t *state, i_node_t *parent_i_node);
