#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_shared.h"
#include "fs_internal.h"
#include "fs_block_manager.h"
#include "fs_i_node_manager.h"
#include "fs_file_table_manager.h"

#include "fs_utils.h"

#include "fs_state.h"

child_slot_and_block_result_t get_free_child_slot(const uint32_t parent_i_node_index) {
    i_node_t *parent_i_node = &i_node_table[parent_i_node_index];
    microkit_debug_puts(OUTPUT_VERBOSITY, "checking parent ");
    microkit_debug_put32(OUTPUT_VERBOSITY, parent_i_node_index);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    uint32_t *indirect_block_data = (uint32_t *)&blocks[parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (int i = 0; i < parent_i_node->blocks_used; i++) {
        microkit_debug_puts(OUTPUT_VERBOSITY, "checking block ");
        microkit_debug_put32(OUTPUT_VERBOSITY, i);
        microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node->block_indices[i];
        } else {
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)&blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            microkit_debug_puts(OUTPUT_VERBOSITY, "checking slot ");
            microkit_debug_put32(OUTPUT_VERBOSITY, j);
            microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
            if (child_entries[j].name[0] == '\0') {
                return (child_slot_and_block_result_t){block_index, j, FS_OK};
            }
        }
    }
    microkit_debug_puts(OUTPUT_VERBOSITY, "need new block\n");
    block_id_result_t new_block = allocate_block();
    if (new_block.return_code != FS_OK) {
        return (child_slot_and_block_result_t){0, 0, new_block.return_code};
    }

    zero_block(blocks[new_block.index].data);
    if (parent_i_node->blocks_used < DIRECT_BLOCKS_PER_INODE) {
        parent_i_node->block_indices[parent_i_node->blocks_used] = new_block.index;
    } else {
        if (parent_i_node->blocks_used == DIRECT_BLOCKS_PER_INODE) {
            block_id_result_t indirect_block = allocate_block();
            if (indirect_block.return_code != FS_OK) {
                release_block(new_block.index);
                return (child_slot_and_block_result_t){0, 0, indirect_block.return_code};
            }
            parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE] = indirect_block.index;
        }
        uint32_t *indirect_block_data = (uint32_t *)&blocks[parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
        indirect_block_data[parent_i_node->blocks_used - DIRECT_BLOCKS_PER_INODE] = new_block.index;
    }
    parent_i_node->blocks_used += 1;
    return (child_slot_and_block_result_t){new_block.index, 0, FS_OK};
}


i_node_result_t add_entry(const uint32_t parent_i_node_index, unsigned char *name, const permissions_t permissions,
                          const uint8_t client_id, const uint32_t block_index, const uint32_t entry_index,
                          const int is_directory) {
    microkit_debug_puts(OUTPUT_VERBOSITY, name);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    if (!valid_name(name)) {
        (void)client_id;
        return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
    }
    i_node_result_t new_i_node_info = allocate_i_node();
    if (new_i_node_info.return_code != FS_OK) {
        return new_i_node_info;
    }
    i_node_t *parent_i_node = &i_node_table[parent_i_node_index];
    child_entry_t *child_entries = (child_entry_t *)&blocks[block_index].data;
    copy_string_from_buffer(name, child_entries[entry_index].name, MAX_NAME_LENGTH);
    microkit_debug_puts(OUTPUT_VERBOSITY, "parent ");
    microkit_debug_put32(OUTPUT_VERBOSITY, parent_i_node_index);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    microkit_debug_puts(OUTPUT_VERBOSITY, "block ");
    microkit_debug_put32(OUTPUT_VERBOSITY, block_index);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    microkit_debug_puts(OUTPUT_VERBOSITY, "entry ");
    microkit_debug_put32(OUTPUT_VERBOSITY, entry_index);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    child_entries[entry_index].i_node_index = new_i_node_info.index;

    block_id_result_t new_block = allocate_block();
    if (new_block.return_code != FS_OK) {
        release_i_node(new_i_node_info.index);
        return (i_node_result_t){-1, new_block.return_code};
    }

    if (is_directory) {
        zero_block(blocks[new_block.index].data);
    }

    parent_i_node->entry_size += 1;

    i_node_table[new_i_node_info.index].mode = IN_USE_BIT_SET | (is_directory << IS_DIRECTORY_BIT_START) | (permissions << PERMISSION_BITS_START); // not deleted, in use, dir, permissions
    i_node_table[new_i_node_info.index].owner_id = client_id;
    i_node_table[new_i_node_info.index].block_indices[0] = new_block.index;
    i_node_table[new_i_node_info.index].entry_size = 0;
    i_node_table[new_i_node_info.index].blocks_used = 1;

    return new_i_node_info;
}


fs_result_t delete_directory_contents(const uint32_t i_node_index) {
    i_node_t *dir_i_node = &i_node_table[i_node_index];
    uint32_t *indirect_block_data = (uint32_t *)&blocks[dir_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (int i = 0; i < dir_i_node->blocks_used; i++) {
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = dir_i_node->block_indices[i];
        } else {
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }
        microkit_debug_puts(OUTPUT_VERBOSITY, "deleting block ");
        microkit_debug_put32(OUTPUT_VERBOSITY, block_index);
        microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
        child_entry_t *child_entries = (child_entry_t *)&blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] == '\0') {
                continue;
            }
            if (i_node_table[child_entries[j].i_node_index].mode & IS_DIRECTORY_BIT_SET) {
                fs_result_t res = delete_directory_contents(child_entries[j].i_node_index);
                if (res != FS_OK) {
                    return res;
                }
            } else {
                fs_result_t res = close_file_by_i_node_index(0, child_entries[j].i_node_index);
                if (res != FS_OK) {
                    return res;
                }
            }
            if (is_i_node_open(child_entries[j].i_node_index)) {
                i_node_table[child_entries[j].i_node_index].mode |= IS_DELETED_BIT_SET;
            } else {
                release_i_node(child_entries[j].i_node_index);
            }
            child_entries[j].name[0] = '\0';
        }
    }
    dir_i_node->entry_size = 0;
    dir_i_node->blocks_used = 0;
    return FS_OK;
}

void defragment_directory(i_node_t *parent_i_node) {
    microkit_debug_puts(OUTPUT_VERBOSITY, "defragmenting directory i node ");
    microkit_debug_put32(OUTPUT_VERBOSITY, parent_i_node - i_node_table);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    uint32_t *indirect_block_data = (uint32_t *)&blocks[parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    int filling_block_index = 0;
    int last_free_child_index = -1;
    int current_child_index = 0;
    uint32_t filling_block;
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
                if (last_free_child_index == -1) {
                    last_free_child_index = current_child_index;
                    filling_block_index = i;
                    if (i < DIRECT_BLOCKS_PER_INODE) {
                        filling_block = parent_i_node->block_indices[filling_block_index];
                    } else {
                        filling_block = indirect_block_data[filling_block_index - DIRECT_BLOCKS_PER_INODE];
                    }
                }
            } else {
                if (last_free_child_index != -1) {
                    copy_string_from_buffer(child_entries[j].name, ((child_entry_t *)&blocks[filling_block].data)[last_free_child_index].name, MAX_NAME_LENGTH);
                    ((child_entry_t *)&blocks[filling_block].data)[last_free_child_index].i_node_index = child_entries[j].i_node_index;
                    child_entries[j].name[0] = '\0';
                    while (((child_entry_t *)&blocks[filling_block].data)[last_free_child_index].name[0] != '\0') {
                        last_free_child_index++;
                        if (block_index == filling_block && last_free_child_index >= j) {
                            last_free_child_index = -1;
                            break;
                        }
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
            }
            current_child_index++;
        }
    }
}