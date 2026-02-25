
#pragma once

#include <stdint.h>

#include "fs_internal.h"

block_id_result_t allocate_block(void);
void release_block(uint32_t block_index);
void release_indirect_block(uint32_t indirect_block_index, int size_in_blocks);
