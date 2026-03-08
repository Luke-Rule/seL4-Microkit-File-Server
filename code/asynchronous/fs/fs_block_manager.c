#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../debug_output.h"
#include "include/fs_buffer_manager.h"
#include "include/fs_shared.h"
#include "include/fs_internal.h"
#include "include/fs_state.h"

block_id_result_t allocate_block(void) {
    for (size_t i = 0; i < MAX_NUMBER_OF_BLOCKS; i++) {
        if (block_table[i] == 0) {
            block_table[i] = 1;
            return (block_id_result_t){i, FS_OK};
        }
    }
    return (block_id_result_t){0, FS_ERR_NO_BLOCKS_REMAINING};
}


void release_block(const size_t block_index) {
    if (block_index < MAX_NUMBER_OF_BLOCKS && block_table[block_index] == 1) {
        block_table[block_index] = 0;
    }
}


void release_indirect_block(const size_t indirect_block_index, const size_t size_in_blocks) {
    size_t *indirect_entries = (size_t *)&blocks[indirect_block_index].data;
    for (size_t i = 0; i < size_in_blocks; i++) {
        release_block(indirect_entries[i]);
    }
}