#include <stdint.h>
#include <stddef.h>
#include "fs_buffer_manager.h"
#include "fs_shared.h"
#include "fs_internal.h"
#include "fs_block_manager.h"

#include "fs_utils.h"

#include "fs_state.h"


i_node_result_t allocate_i_node(void) {
    for (size_t i = 0; i < MAX_NUMBER_OF_INODES; i++) {
        if ((i_node_table[i].mode & 0x1) == 0) {
            i_node_table[i].mode |= 0x1;
            return (i_node_result_t){i, FS_OK};
        }
    }

    microkit_dbg_puts("cant allocate i node\n");
    return (i_node_result_t){0, FS_ERR_INODE_TABLE_FULL};
}


void release_i_node(const uint32_t i_node_index) {
    if (i_node_index < MAX_NUMBER_OF_INODES) {
        i_node_table[i_node_index].mode = 0;
        for (size_t i = 0; i < i_node_table[i_node_index].blocks_used; i++) {
            uint32_t block_index;
            if (i >= DIRECT_BLOCKS_PER_INODE) {
                release_indirect_block(i_node_table[i_node_index].block_indices[DIRECT_BLOCKS_PER_INODE],
                                      i_node_table[i_node_index].blocks_used - DIRECT_BLOCKS_PER_INODE);
                return;
            }
            
            block_index = i_node_table[i_node_index].block_indices[i];
            release_block(block_index);
        }
    }
}


i_node_result_t get_i_node_index(unsigned char *path, const uint32_t parent_i_node_index,
                                 const uint8_t client_id, const int get_parent) {
    microkit_dbg_puts("resolving path: ");
    microkit_dbg_puts((const char *)path);
    microkit_dbg_puts("\n");
    if (path[0] != '/') {
        return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
    }
    path = &path[1];
    if (path[0] == '\0') {
        return (i_node_result_t){parent_i_node_index, FS_OK};
    }
    i_node_t *parent_i_node = &i_node_table[parent_i_node_index];
    uint32_t *indirect_block_data = (uint32_t *)&blocks[parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (int i = 0; i < parent_i_node->blocks_used; i++) {
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node->block_indices[i];
        } else {
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)&blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] == '\0') {
                continue;
            }
            int cmp_result = compare_names(path, child_entries[j].name);
            if (cmp_result == FULL_PATH_EQUAL) {
                if (get_parent) {
                    return (i_node_result_t){parent_i_node_index, FS_OK};
                }
                return (i_node_result_t){child_entries[j].i_node_index, FS_OK};
            } else if (cmp_result == PATH_SEGMENT_EQUAL) {
                while (*path != '/') {
                    path = &path[1];
                }
                if (i_node_table[child_entries[j].i_node_index].mode & IS_DIRECTORY_BIT_SET) {
                    if (!valid_permissions(&i_node_table[child_entries[j].i_node_index], client_id, PERM_EXECUTE)) {
                        return (i_node_result_t){-1, FS_ERR_PERMISSION};
                    }
                    return get_i_node_index(path, child_entries[j].i_node_index, client_id, get_parent);
                } else {
                    return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
                }
            }
        }
    }
    microkit_dbg_puts("i node not found\n");
    return (i_node_result_t){-1, FS_ERR_NOT_FOUND};
}