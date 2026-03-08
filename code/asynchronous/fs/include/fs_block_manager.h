
#pragma once

#include <stdint.h>

#include "fs_internal.h"

block_id_result_t allocate_block(void);
void release_block(const size_t block_index);
void release_indirect_block(const size_t indirect_block_index, const size_t size_in_blocks);
