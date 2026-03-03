#include <stdint.h>
#include <stddef.h>
#include "fs_buffer_manager.h"
#include "fs_shared.h"
#include "fs_internal.h"
#include "fs_block_manager.h"
#include "fs_utils.h"

#include "fs_state.h"

block_search_result_t get_inode_block_index_from_file_index(const uint32_t file_index) {
    uint32_t block_index = file_index / BLOCK_SIZE;
    uint32_t block_offset = file_index % BLOCK_SIZE;
    if (block_index < DIRECT_BLOCKS_PER_INODE) {
        return (block_search_result_t){block_index, block_offset, 0};
    } else {
        return (block_search_result_t){DIRECT_BLOCKS_PER_INODE - block_index, block_offset, 1};
    }
}


fs_result_t copy_bytes_i_node(i_node_t *i_node, uint8_t *client_buffer, size_t length,
                              file_descriptor_t *fd, const int rnw) {
    size_t buffer_index = 0;
    block_search_result_t block_info = get_inode_block_index_from_file_index(fd->cursor_position);
    uint32_t *indirect_block_data = (uint32_t *)&blocks[i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    while (length > 0) {
        uint32_t block_index;
        if (block_info.is_indirect) {
            block_index = indirect_block_data[block_info.i_node_block_index];
        } else {
            block_index = i_node->block_indices[block_info.i_node_block_index];
        }
        uint8_t *block_data = (uint8_t *)&blocks[block_index];
        size_t bytes_available_in_block = BLOCK_SIZE - block_info.block_offset;
        size_t bytes_this_iteration = (length < bytes_available_in_block) ? length : bytes_available_in_block;
        if (rnw) {
            microkit_dbg_puts("reading block: ");
            microkit_dbg_put32(block_index);
            microkit_dbg_puts("\n");
            copy_data_from_buffer(&block_data[block_info.block_offset], &client_buffer[buffer_index], bytes_this_iteration);
        } else {
            copy_data_from_buffer(&client_buffer[buffer_index], &block_data[block_info.block_offset], bytes_this_iteration);
        }
        buffer_index += bytes_this_iteration;
        length -= bytes_this_iteration;
        if (length == 0) {
            break;
        }
        if (block_info.is_indirect) {
            block_info.i_node_block_index++;
        } else {
            if (block_info.i_node_block_index >= DIRECT_BLOCKS_PER_INODE - 1) {
                if (i_node->blocks_used <= DIRECT_BLOCKS_PER_INODE) {
                    microkit_dbg_puts("allocating indirect block\n");
                    block_id_result_t new_block = allocate_block();
                    if (new_block.return_code != FS_OK) {
                        return FS_ERR_NO_BLOCKS_REMAINING;
                    }
                    i_node->block_indices[DIRECT_BLOCKS_PER_INODE] = new_block.index;
                    indirect_block_data = (uint32_t *)&blocks[i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
                }
                
                block_info.is_indirect = 1;
                block_info.i_node_block_index = 0;
            } else {
                block_info.i_node_block_index++;
            }
        }
        block_info.block_offset = 0;
        if (!rnw){
            if (i_node->blocks_used <= block_info.i_node_block_index + (block_info.is_indirect ? DIRECT_BLOCKS_PER_INODE : 0)) {
                block_id_result_t new_block = allocate_block();
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
    }
    fd->cursor_position += buffer_index;
    if (!rnw && fd->cursor_position > i_node->entry_size) {
        i_node->entry_size = fd->cursor_position;
    }
    return FS_OK;
}