
#pragma once

#include <stdint.h>

#include "fs_internal.h"

block_id_result_t allocate_block(fs_state_t *state);
void release_block(fs_state_t *state, const size_t block_index);
void release_indirect_block(fs_state_t *state, const size_t indirect_block_index, const size_t size_in_blocks);
