#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"
#include "fs_internal.h"

block_id_result_t allocate_block(fs_state_t *state) {
    for (size_t i = 0; i < MAX_NUMBER_OF_BLOCKS; i++) {
        if (state->block_table[i] == false) {
            state->block_table[i] = true;
            return (block_id_result_t){i, FS_OK};
        }
    }
    return (block_id_result_t){0, FS_ERR_NO_BLOCKS_REMAINING};
}


void release_block(fs_state_t *state, const size_t block_index) {
    if (block_index < MAX_NUMBER_OF_BLOCKS && state->block_table[block_index] == true) {
        state->block_table[block_index] = false;
    }
}


void release_indirect_block(fs_state_t *state, const size_t indirect_block_index, const size_t size_in_blocks) {
    size_t *indirect_entries = (size_t *)&state->blocks[indirect_block_index].data;
    for (size_t i = 0; i < size_in_blocks; i++) {
        release_block(state, indirect_entries[i]);
    }
}