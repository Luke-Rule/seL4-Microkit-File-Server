#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_internal.h"
#include "fs_block_manager.h"
#include "fs_utils.h"


i_node_result_t allocate_i_node(fs_state_t *state) {
    for (size_t i = 0; i < MAX_NUMBER_OF_INODES; i++) {
        if ((state->i_node_table[i].mode & IN_USE_BIT_SET) == 0) {
            state->i_node_table[i].mode |= IN_USE_BIT_SET;
            return (i_node_result_t){i, FS_OK};
        }
    }

    microkit_debug_puts(OUTPUT_VERBOSITY, "cant allocate i node\n");
    return (i_node_result_t){0, FS_ERR_INODE_TABLE_FULL};
}


void release_i_node(fs_state_t *state, const uint32_t i_node_index) {
    if (i_node_index < MAX_NUMBER_OF_INODES) {
        state->i_node_table[i_node_index].mode = 0;
        for (size_t i = 0; i < state->i_node_table[i_node_index].blocks_used; i++) {
            size_t block_index;
            if (i >= DIRECT_BLOCKS_PER_INODE) {
                release_indirect_block(state, state->i_node_table[i_node_index].block_indices[DIRECT_BLOCKS_PER_INODE],
                                       state->i_node_table[i_node_index].blocks_used - DIRECT_BLOCKS_PER_INODE);
                return;
            }
            
            block_index = state->i_node_table[i_node_index].block_indices[i];
            release_block(state, block_index);
        }
    }
}


i_node_result_t get_i_node_index(fs_state_t *state, unsigned char *path, const uint32_t parent_i_node_index,
                                 const uint8_t client_id, const bool get_parent) {
    microkit_debug_puts(OUTPUT_VERBOSITY, "resolving path: ");
    microkit_debug_puts(OUTPUT_VERBOSITY, (const char *)path);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    if (path[0] != '/') {
        return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
    }
    path = &path[1];
    if (path[0] == '\0') {
        return (i_node_result_t){parent_i_node_index, FS_OK};
    }
    i_node_t *parent_i_node = &state->i_node_table[parent_i_node_index];
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
                if (state->i_node_table[child_entries[j].i_node_index].mode & IS_DIRECTORY_BIT_SET) {
                    if (!valid_permissions(&state->i_node_table[child_entries[j].i_node_index], client_id, PERM_EXECUTE)) {
                        return (i_node_result_t){-1, FS_ERR_PERMISSION};
                    }
                    return get_i_node_index(state, path, child_entries[j].i_node_index, client_id, get_parent);
                } else {
                    return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
                }
            }
        }
    }
    microkit_debug_puts(OUTPUT_VERBOSITY, "i node not found\n");
    return (i_node_result_t){-1, FS_ERR_NOT_FOUND};
}