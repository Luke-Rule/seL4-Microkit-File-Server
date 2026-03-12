#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_internal.h"
#include "fs_block_manager.h"
#include "fs_i_node_manager.h"
#include "fs_file_table_manager.h"
#include "fs_utils.h"

child_slot_and_block_result_t get_free_child_slot(fs_state_t *state, const uint32_t parent_i_node_index) {
    i_node_t *parent_i_node = &state->i_node_table[parent_i_node_index];
    size_t *indirect_block_data = (size_t *)&state->blocks[parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;

    for (size_t i = 0; i < parent_i_node->blocks_used; i++) {
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node->block_indices[i];
        } else {
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }

        child_entry_t *child_entries = (child_entry_t *)&state->blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] == '\0') {
                return (child_slot_and_block_result_t){block_index, j, FS_OK};
            }
        }
    }

    // if we get here, there are no free child slots in existing blocks, we need to allocate a new block for child entries
    block_id_result_t new_block = allocate_block(state);
    if (new_block.return_code != FS_OK) {
        return (child_slot_and_block_result_t){0, 0, new_block.return_code};
    }

    // dir blocks must be zeroed so that all child slots are initially free
    zero_block(state->blocks[new_block.index].data);

    // add block to parent i-node
    if (parent_i_node->blocks_used < DIRECT_BLOCKS_PER_INODE) {
        parent_i_node->block_indices[parent_i_node->blocks_used] = new_block.index;
    } else {
        // if we are adding the first block to the indirect block, we need to allocate the indirect block first
        if (parent_i_node->blocks_used == DIRECT_BLOCKS_PER_INODE) {
            block_id_result_t indirect_block = allocate_block(state);
            if (indirect_block.return_code != FS_OK) {
                release_block(state, new_block.index);
                return (child_slot_and_block_result_t){0, 0, indirect_block.return_code};
            }

            parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE] = indirect_block.index;
        }
        size_t *indirect_block_data = (size_t *)&state->blocks[parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
        indirect_block_data[parent_i_node->blocks_used - DIRECT_BLOCKS_PER_INODE] = new_block.index;
    }

    parent_i_node->blocks_used += 1;
    return (child_slot_and_block_result_t){new_block.index, 0, FS_OK};
}


fs_result_t delete_directory_contents(fs_state_t *state, const uint32_t i_node_index) {
    i_node_t *dir_i_node = &state->i_node_table[i_node_index];
    size_t *indirect_block_data = (size_t *)&state->blocks[dir_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (size_t i = 0; i < dir_i_node->blocks_used; i++) {
        size_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = dir_i_node->block_indices[i];
        } else {
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }

        child_entry_t *child_entries = (child_entry_t *)&state->blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] == '\0') {
                continue;
            }
            // if the child entry is a directory, we need to recursively delete its contents before we can delete the i-node
            if (state->i_node_table[child_entries[j].i_node_index].mode & IS_DIRECTORY_BIT_SET) {
                fs_result_t res = delete_directory_contents(state, child_entries[j].i_node_index);
                if (res != FS_OK) {
                    return res;
                }
            } else {
                fs_result_t res = close_file_by_i_node_index(state, 0, child_entries[j].i_node_index);
                if (res != FS_OK) {
                    return res;
                }
                // if another client has the file open, we cannot delete it yet, it will be deleted upon final close
                if (is_i_node_open(state, child_entries[j].i_node_index)) {
                    state->i_node_table[child_entries[j].i_node_index].mode |= IS_DELETED_BIT_SET;
                    break;
                }
            }

            release_i_node(state, child_entries[j].i_node_index);
        }
    }

    return FS_OK;
}

// called when re-arranging children would allow a block free 
void defragment_directory(fs_state_t *state, i_node_t *parent_i_node) {
    size_t filling_block_index = 0;
    size_t last_free_child_index = -1;
    size_t current_child_index = 0;
    size_t filling_block;
    size_t *indirect_block_data = (size_t *)&state->blocks[parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (size_t i = 0; i < parent_i_node->blocks_used; i++) {
        size_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node->block_indices[i];
        } else {
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }

        child_entry_t *child_entries = (child_entry_t *)&state->blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            // if found free entry for first time
            if (last_free_child_index == -1 && child_entries[j].name[0] == '\0') {
                // set index, and the block it resides within
                last_free_child_index = current_child_index;
                filling_block_index = i;
                if (i < DIRECT_BLOCKS_PER_INODE) {
                    filling_block = parent_i_node->block_indices[filling_block_index];
                } else {
                    filling_block = indirect_block_data[filling_block_index - DIRECT_BLOCKS_PER_INODE];
                }
            // if found occupied entry and have previously found a free entry
            } else if (last_free_child_index != -1) {
                // copy entry into free slot
                copy_string_from_buffer(child_entries[j].name, ((child_entry_t *)&state->blocks[filling_block].data)[last_free_child_index].name, MAX_NAME_LENGTH);
                ((child_entry_t *)&state->blocks[filling_block].data)[last_free_child_index].i_node_index = child_entries[j].i_node_index;
                
                // free old slot
                child_entries[j].name[0] = '\0';
                
                // loop to check if there is free slot between the last free slot and current index
                while (((child_entry_t *)&state->blocks[filling_block].data)[last_free_child_index].name[0] != '\0') {
                    last_free_child_index++;
                    // if reach current index, go back to regular loop
                    if (block_index == filling_block && last_free_child_index >= j) {
                        // need to find new free slot
                        last_free_child_index = -1;
                        break;
                    }
                    // need to enter next block
                    if (last_free_child_index >= MAX_CHILD_ENTRIES_PER_BLOCK) {
                        last_free_child_index = 0;
                        filling_block_index += 1;
                        if (filling_block_index < DIRECT_BLOCKS_PER_INODE) {
                            filling_block = parent_i_node->block_indices[filling_block_index];
                        } else {
                            filling_block = indirect_block_data[filling_block_index - DIRECT_BLOCKS_PER_INODE];
                        }
                    }
                }
            }
            
            current_child_index++;
        }
    }
}