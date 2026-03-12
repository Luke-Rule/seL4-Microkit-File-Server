#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_internal.h"
#include "fs_block_manager.h"
#include "fs_utils.h"

block_search_result_t get_inode_block_index_from_file_cursor_position(const size_t file_cursor_position) {
    // a file can span multiple blocks
    size_t block_index = file_cursor_position / BLOCK_SIZE;
    size_t block_offset = file_cursor_position % BLOCK_SIZE;
    if (block_index < DIRECT_BLOCKS_PER_INODE) {
        return (block_search_result_t){block_index, block_offset, 0};
    } else {
        return (block_search_result_t){DIRECT_BLOCKS_PER_INODE - block_index, block_offset, 1};
    }
}


fs_result_t copy_bytes_i_node(fs_state_t *state, i_node_t *i_node, uint8_t *client_buffer, size_t length,
                              file_descriptor_t *fd, const bool rnw) {

    size_t buffer_index = 0;
    // get starting point
    block_search_result_t block_info = get_inode_block_index_from_file_cursor_position(fd->cursor_position);
    size_t *indirect_block_data = (size_t *)&state->blocks[i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    // to check whether we require a new block - writing past existing size of file
    size_t current_total_block_index = block_info.i_node_block_index + (block_info.is_indirect ? DIRECT_BLOCKS_PER_INODE : 0);
    
    while (length > 0) {
        size_t block_index;
        if (block_info.is_indirect) {
            block_index = indirect_block_data[block_info.i_node_block_index];
        } else {
            block_index = i_node->block_indices[block_info.i_node_block_index];
        }
        uint8_t *block_data = (uint8_t *)&state->blocks[block_index];
        
        // get amount of bytes to copy from current block
        size_t bytes_remaining_in_block = BLOCK_SIZE - block_info.block_offset;
        size_t bytes_this_iteration = (length < bytes_remaining_in_block) ? length : bytes_remaining_in_block;
        
        // read or write data
        if (rnw) {
            copy_data_from_buffer(&block_data[block_info.block_offset], &client_buffer[buffer_index], bytes_this_iteration);
        } else {
            copy_data_from_buffer(&client_buffer[buffer_index], &block_data[block_info.block_offset], bytes_this_iteration);
        }
        
        buffer_index += bytes_this_iteration;
        length -= bytes_this_iteration;
        if (length == 0) {
            break;
        }

        // if op not complete get next block to access
        block_info.block_offset = 0;
        if (block_info.is_indirect) {
            // if we are already accessing indirect blocks, we just need to increment the index to the next entry
            block_info.i_node_block_index++;
        } else {
            // otherwise we need to check if we need to switch to indirect blocks or just move to the next direct block
            if (block_info.i_node_block_index >= DIRECT_BLOCKS_PER_INODE - 1) {
                // we have read the last direct block so need to switch to indirect blocks but the indirect block may not have been allocated yet
                if (i_node->blocks_used <= DIRECT_BLOCKS_PER_INODE) {
                    if (rnw) {
                        // if reading, then we are done since there is no more data to read
                        fd->cursor_position += buffer_index;
                        // but return the requested amount was invalid
                        return FS_ERR_OUT_OF_BOUNDS;
                    }

                    // allocate indirect block
                    block_id_result_t new_block = allocate_block(state);
                    if (new_block.return_code != FS_OK) {
                        return FS_ERR_NO_BLOCKS_REMAINING;
                    }
                    i_node->block_indices[DIRECT_BLOCKS_PER_INODE] = new_block.index;
                    indirect_block_data = (size_t *)&state->blocks[i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
                }
                // switch to indirect blocks
                block_info.is_indirect = true;
                block_info.i_node_block_index = 0;
            } else {
                block_info.i_node_block_index++;
            }
        }
        current_total_block_index++;
        // if writing and the block we need to access doesnt exist, we need to allocate and add it the i-node it before we can continue
        if (!rnw && current_total_block_index >= i_node->blocks_used) {
            block_id_result_t new_block = allocate_block(state);
            if (new_block.return_code != FS_OK) {
                return FS_ERR_NO_BLOCKS_REMAINING;
            }
            i_node->blocks_used += 1;
            if (block_info.is_indirect) {
                indirect_block_data[block_info.i_node_block_index] = new_block.index;
            } else {
                i_node->block_indices[block_info.i_node_block_index] = new_block.index;
            }
        }
    }

    fd->cursor_position += buffer_index;
    if (!rnw && fd->cursor_position > i_node->entry_size) {
        i_node->entry_size = fd->cursor_position;
    }
    
    return FS_OK;
}