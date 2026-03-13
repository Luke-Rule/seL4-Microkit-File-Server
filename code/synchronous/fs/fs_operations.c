#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../debug_output.h"

#include "include/fs_shared.h"
#include "fs_internal.h"
#include "fs_block_manager.h"
#include "fs_block_data_manager.h"
#include "fs_i_node_manager.h"
#include "fs_directory_manager.h"
#include "fs_file_table_manager.h"
#include "fs_utils.h"

// ------------------------------ Directory entry management functions ------------------------------- //

i_node_result_t add_entry(fs_state_t *state, const uint32_t parent_i_node_index, const unsigned char *name,
                          const permissions_t permissions, const uint8_t client_id,
                          const child_slot_and_block_result_t slot_info, const bool is_directory) {

    if (!valid_name(name)) {
        return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
    }

    // get i-node for new entry
    i_node_result_t new_i_node_info = allocate_i_node(state);
    if (new_i_node_info.return_code != FS_OK) {
        return new_i_node_info;
    }

    i_node_t *parent_i_node = &state->i_node_table[parent_i_node_index];
    child_entry_t *child_entries = (child_entry_t *)&state->blocks[slot_info.block_index].data;

    // add name and i node to parent dir
    copy_string_from_buffer(name, child_entries[slot_info.entry_index].name, MAX_NAME_LENGTH);
    child_entries[slot_info.entry_index].i_node_index = new_i_node_info.index;

    // add block to i-node
    block_id_result_t new_block = allocate_block(state);
    if (new_block.return_code != FS_OK) {
        release_i_node(state, new_i_node_info.index);
        return (i_node_result_t){-1, new_block.return_code};
    }

    if (is_directory) {
        zero_block(state->blocks[new_block.index].data);
    }

    parent_i_node->entry_size += 1;

    state->i_node_table[new_i_node_info.index].mode = IN_USE_BIT_SET | (is_directory << DIRECTORY_BIT_START) | (permissions << PERMISSION_BITS_START);
    state->i_node_table[new_i_node_info.index].owner_id = client_id;
    state->i_node_table[new_i_node_info.index].block_indices[0] = new_block.index;
    state->i_node_table[new_i_node_info.index].entry_size = 0;
    state->i_node_table[new_i_node_info.index].blocks_used = 1;

    return new_i_node_info;
}


i_node_result_t create_entry(fs_state_t *state, unsigned char *client_buffer, const uint32_t parent_i_node_index,
                             const permissions_t permissions, const uint8_t client_id,
                             const bool is_directory) {

    if (client_buffer[0] != '/') {
        return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
    }

    // skip past segment delimeter
    client_buffer = &client_buffer[1];

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

            int32_t cmp_result = compare_names(client_buffer, child_entries[j].name);
            if (cmp_result == FULL_PATH_EQUAL) {
                return (i_node_result_t){-1, FS_ERR_ALREADY_EXISTS};
            }
            if (cmp_result == PATH_SEGMENT_EQUAL) {
                // skip over subdir name we are entering 
                while (*client_buffer != '/') {
                    client_buffer = &client_buffer[1];
                }

                if (state->i_node_table[child_entries[j].i_node_index].mode & IS_DIRECTORY_BIT_SET) {
                    if (!valid_permissions(&state->i_node_table[child_entries[j].i_node_index], client_id, PERM_EXECUTE)) {
                        return (i_node_result_t){-1, FS_ERR_PERMISSION};
                    }

                    // recurse on subdir
                    return create_entry(state, client_buffer, child_entries[j].i_node_index, permissions, client_id,
                                        is_directory);
                }
                
                // cannot enter file
                return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
            }
        }
    }
    
    // if reach here we have a non colliding file name (NOT a path)
    // anyone can add entries to root
    if (parent_i_node_index != ROOT_DIRECTORY_I_NODE_INDEX &&
        parent_i_node->owner_id != client_id &&
        !valid_permissions(parent_i_node, client_id, PERM_WRITE)) {
        return (i_node_result_t){-1, FS_ERR_PERMISSION};
    }

    child_slot_and_block_result_t slot_info = get_free_child_slot(state, parent_i_node_index);
    if (slot_info.return_code != FS_OK) {
        return (i_node_result_t){-1, slot_info.return_code};
    }

    return add_entry(state, parent_i_node_index, client_buffer, permissions, client_id, slot_info, is_directory);
}


fs_result_t delete_entry_operation(fs_state_t *state, const uint8_t client_id, unsigned char *client_buffer) {
    i_node_result_t i_node_index = get_i_node_index(state, client_buffer, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        return i_node_index.return_code;
    }
    if (state->i_node_table[i_node_index.index].owner_id != client_id && !valid_permissions(&state->i_node_table[i_node_index.index], client_id, PERM_WRITE)) {
        return FS_ERR_PERMISSION;
    }
    if (state->i_node_table[i_node_index.index].mode & IS_DELETED_BIT_SET) {
        // if it's already slated to be deleted and it is still open by multiple clients, return as successful,
        // it will be removed when the last file descriptor is closed
        if (is_i_node_open_by_other_client(state, i_node_index.index, client_id)) {
            return FS_OK;
        }
        // otherwise we can treat this delete as the final close (we have already done the removal processing below)
        release_i_node(state, i_node_index.index);
        if (is_i_node_open_by_client(state, i_node_index.index, client_id)) {
            return close_file_by_i_node_index(state, client_id, i_node_index.index);
        }
        return FS_OK;
    }

    // remove entry from parent dir
    i_node_result_t parent_i_node = get_i_node_index(state, client_buffer, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_PARENT_I_NODE);
    if (parent_i_node.return_code != FS_OK) {
        return parent_i_node.return_code;
    }

    i_node_t *parent_i_node_ptr = &state->i_node_table[parent_i_node.index];
    size_t *indirect_block_data = (size_t *)&state->blocks[parent_i_node_ptr->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (size_t i = 0; i < parent_i_node_ptr->blocks_used; i++) {
        size_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node_ptr->block_indices[i];
        } else {
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }

        child_entry_t *child_entries = (child_entry_t *)&state->blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].i_node_index == i_node_index.index) {
                // represents unused
                child_entries[j].name[0] = '\0';
                parent_i_node_ptr->entry_size -= 1;
                break;
            }
        }
    }

    // a block can be freed if there are over a 2 blocks worth of free child entry slots in the dir (x2 avoids repeated alloctation-deallocation)
    if ((size_t)(parent_i_node_ptr->entry_size / MAX_CHILD_ENTRIES_PER_BLOCK) + 1 < parent_i_node_ptr->blocks_used) {
        // shift these all to the first blocks worth of child entries
        defragment_directory(state, parent_i_node_ptr);

        // free last block
        size_t block_to_free_index = parent_i_node_ptr->blocks_used - 1;
        size_t block_index;
        if (block_to_free_index < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node_ptr->block_indices[block_to_free_index];
            parent_i_node_ptr->block_indices[block_to_free_index] = 0;
        } else {
            block_index = indirect_block_data[block_to_free_index - DIRECT_BLOCKS_PER_INODE];
            indirect_block_data[block_to_free_index - DIRECT_BLOCKS_PER_INODE] = 0;
        }

        release_block(state, block_index);
        parent_i_node_ptr->blocks_used -= 1;
    }

    if (state->i_node_table[i_node_index.index].mode & IS_DIRECTORY_BIT_SET) {
        // recursively delete dir contents
        fs_result_t res = delete_directory_contents(state, i_node_index.index);
        release_i_node(state, i_node_index.index);
        return res;
    } else {
        // if its a file, only remove i-node when all fds to it are closed
        if (is_i_node_open_by_other_client(state, i_node_index.index, client_id)) {
            state->i_node_table[i_node_index.index].mode |= IS_DELETED_BIT_SET;
            return FS_OK;
        }

        release_i_node(state, i_node_index.index);
        if (is_i_node_open_by_client(state, i_node_index.index, client_id)) {
            return close_file_by_i_node_index(state, client_id, i_node_index.index);
        } 

        return FS_OK;
    }
}


fs_result_t set_entry_permissions_operation(fs_state_t *state, const uint8_t client_id,
                                            const permissions_t permissions, unsigned char *client_buffer) {

    i_node_result_t i_node_index = get_i_node_index(state, client_buffer, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        return i_node_index.return_code;
    }

    if (state->i_node_table[i_node_index.index].owner_id != client_id) {
        return FS_ERR_PERMISSION;
    }

    // clear perms and set new
    const uint8_t perm_mask = (uint8_t)(0b111u << PERMISSION_BITS_START);
    state->i_node_table[i_node_index.index].mode = (uint8_t)((state->i_node_table[i_node_index.index].mode & ~perm_mask) |
                                                             ((uint8_t)permissions << PERMISSION_BITS_START));

    return FS_OK;
}


fs_result_t get_entry_permissions_operation(fs_state_t *state, const uint8_t client_id, unsigned char *client_buffer) {
    i_node_result_t i_node_index = get_i_node_index(state, client_buffer, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        return i_node_index.return_code;
    }

    client_buffer[0] = (state->i_node_table[i_node_index.index].mode >> PERMISSION_BITS_START) & 0b111;

    return FS_OK;
}


fs_result_t get_entry_size_operation(fs_state_t *state, const uint8_t client_id, unsigned char *client_buffer) {
    i_node_result_t i_node_index = get_i_node_index(state, client_buffer, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        return i_node_index.return_code;
    }

    *((uint32_t *)client_buffer) = state->i_node_table[i_node_index.index].entry_size;

    return FS_OK;
}


fs_result_t entry_exists_operation(fs_state_t *state, const uint8_t client_id, unsigned char *client_buffer) {
    i_node_result_t i_node_index = get_i_node_index(state, client_buffer, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    client_buffer[0] = (i_node_index.return_code == FS_OK) ? 1 : 0;

    return FS_OK;
}

fs_result_t list_directory_operation(fs_state_t *state, const uint8_t client_id, unsigned char *client_buffer) {
    i_node_result_t i_node_index = get_i_node_index(state, client_buffer, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        return i_node_index.return_code;
    }

    i_node_t *dir_i_node = &state->i_node_table[i_node_index.index];
    if (!(dir_i_node->mode & IS_DIRECTORY_BIT_SET)) {
        return FS_ERR_INVALID_PATH;
    }

    if (!valid_permissions(dir_i_node, client_id, PERM_READ)) {
        return FS_ERR_PERMISSION;
    }

    size_t chars_written = 0;
    size_t *indirect_block_data = (size_t *)&state->blocks[dir_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (size_t i = 0; i < dir_i_node->blocks_used; i++) {
        // dont overflow buffer
        if (chars_written >= CLIENT_BUFFER_SIZE - 1) {
            break;
        }

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

            // dont overflow buffer
            const size_t max_amount_to_copy = (MAX_NAME_LENGTH > CLIENT_BUFFER_SIZE - 1 - chars_written) ? 
                                                CLIENT_BUFFER_SIZE - 1 - chars_written: 
                                                MAX_NAME_LENGTH;

            chars_written += copy_string_from_buffer(child_entries[j].name, &client_buffer[chars_written], max_amount_to_copy);
            
            // truncate buffer
            if (chars_written >= CLIENT_BUFFER_SIZE - 1) {
                client_buffer[chars_written - 4] = '.';
                client_buffer[chars_written - 3] = '.';
                client_buffer[chars_written - 2] = '.';
                client_buffer[chars_written - 1] = '\n';
                break;
            }

            // add newline after each entry
            client_buffer[chars_written] = '\n';
            chars_written += 1;
        }
    }

    client_buffer[chars_written] = '\0';
    return FS_OK;
}

// ------------------------------ File operation functions ------------------------------- //

fs_result_t open_file_operation(fs_state_t *state, const uint8_t client_id,
                                const file_open_operations_t requested_operations, unsigned char *client_buffer) {

    i_node_result_t i_node_index = get_i_node_index(state, client_buffer, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        return i_node_index.return_code;
    }

    if (state->i_node_table[i_node_index.index].mode & IS_DIRECTORY_BIT_SET) {
        return FS_ERR_INVALID_PATH;
    }

    file_id_and_cursor_result_t fd = add_i_node_to_fd_table(state, client_id, i_node_index.index, requested_operations);
    if (fd.return_code != FS_OK) {
        return fd.return_code;
    }

    *((uint32_t *)client_buffer) = fd.file_id;

    return FS_OK;
}


fs_result_t close_file_operation(fs_state_t *state, const uint8_t client_id,
                                 const uint32_t file_descriptor_index) {

    file_descriptor_result_t fd = get_file_descriptor(state, client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        return fd.return_code;
    }

    uint32_t i_node_index = fd.descriptor->i_node_index;
    fd.descriptor->i_node_index = -1;
    fd.descriptor->cursor_position = 0;
    fd.descriptor->valid_operations = 0;

    if (!is_i_node_open(state, i_node_index) && state->i_node_table[i_node_index].mode & IS_DELETED_BIT_SET) {
        release_i_node(state, i_node_index);
    }

    return FS_OK;
}


fs_result_t read_file_operation(fs_state_t *state, const uint8_t client_id,
                                const uint32_t file_descriptor_index, const size_t length,
                                uint8_t *client_buffer) {

    file_descriptor_result_t fd = get_file_descriptor(state, client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        return fd.return_code;
    }

    if (!(fd.descriptor->valid_operations & PERM_READ)) {
        return FS_ERR_PERMISSION;
    }

    fs_result_t return_code = FS_OK;
    i_node_t *i_node = &state->i_node_table[fd.descriptor->i_node_index];

    size_t bytes_to_read = length;
    // limit read to file length
    if (fd.descriptor->cursor_position + length > i_node->entry_size) {
        bytes_to_read = i_node->entry_size - fd.descriptor->cursor_position;
        // signal invalid parameters
        return_code = FS_ERR_OUT_OF_BOUNDS;
    }

    size_t cursor_before = fd.descriptor->cursor_position;
    // leave space for return values
    fs_result_t rc = copy_bytes_i_node(state, i_node, &client_buffer[8], bytes_to_read, fd.descriptor, READ);
    if (rc != FS_OK) {
        return rc;
    
    }
    ((uint32_t *)client_buffer)[0] = fd.descriptor->cursor_position - cursor_before;
    ((uint32_t *)client_buffer)[1] = fd.descriptor->cursor_position;

    return return_code;
}


fs_result_t write_file_operation(fs_state_t *state, const uint8_t client_id,
                                 const uint32_t file_descriptor_index, size_t length,
                                 uint8_t *client_buffer) {

    file_descriptor_result_t fd = get_file_descriptor(state, client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        return fd.return_code;
    }

    if (!(fd.descriptor->valid_operations & PERM_WRITE)) {
        return FS_ERR_PERMISSION;
    }

    fs_result_t return_code = FS_OK;
    i_node_t *i_node = &state->i_node_table[fd.descriptor->i_node_index];
    // limit write to max file size
    if (length + fd.descriptor->cursor_position >= MAX_BLOCKS_PER_FILE * BLOCK_SIZE) {
        length = MAX_BLOCKS_PER_FILE * BLOCK_SIZE - (fd.descriptor->cursor_position) - 1;
        // indicate invalid parameters
        return_code = FS_ERR_MAX_FILE_SIZE_REACHED;
    }

    size_t cursor_before = fd.descriptor->cursor_position;
    fs_result_t rc = copy_bytes_i_node(state, i_node, client_buffer, length, fd.descriptor, WRITE);
    if (rc != FS_OK) {
        return rc;
    }

    ((uint32_t *)client_buffer)[0] = fd.descriptor->cursor_position - cursor_before;
    ((uint32_t *)client_buffer)[1] = fd.descriptor->cursor_position;

    return return_code;
}


fs_result_t seek_file_operation(fs_state_t *state, const uint8_t client_id,
                                const uint32_t file_descriptor_index, const size_t position) {

    file_descriptor_result_t fd = get_file_descriptor(state, client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        return fd.return_code;
    }

    if (position > state->i_node_table[fd.descriptor->i_node_index].entry_size) {
        return FS_ERR_OUT_OF_BOUNDS;
    }

    fd.descriptor->cursor_position = position;

    return FS_OK;
}