#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../debug_output.h"

#include "include/fs_buffer_manager.h"
#include "include/fs_shared.h"
#include "fs_internal.h"
#include "fs_block_manager.h"
#include "fs_block_data_manager.h"
#include "fs_i_node_manager.h"
#include "fs_directory_manager.h"
#include "fs_file_table_manager.h"
#include "include/fs_queue_manager_server.h"
#include "fs_utils.h"

// ------------------------------ Directory entry management functions ------------------------------- //


i_node_result_t add_entry(fs_state_t *state, client_t *client, const uint32_t parent_i_node_index,
                          const unsigned char *name, const permissions_t permissions,
                          const uint8_t client_id, const child_slot_and_block_result_t free_child_slot,
                          const bool is_directory) {

    if (!valid_name(name)) {
        add_completion_entry(client, FS_ERR_INVALID_PATH, 0, 0, SIZE_MAX);
        return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
    }

    i_node_result_t new_i_node_info = allocate_i_node(state);
    if (new_i_node_info.return_code != FS_OK) {
        add_completion_entry(client, new_i_node_info.return_code, 0, 0, SIZE_MAX);
        return new_i_node_info;
    }

    // add entry name and i-node to parent directory
    child_entry_t *child_entries = (child_entry_t *)&state->blocks[free_child_slot.block_index].data;
    copy_string_from_buffer(name, child_entries[free_child_slot.entry_index].name, MAX_NAME_LENGTH);
    child_entries[free_child_slot.entry_index].i_node_index = new_i_node_info.index;
    
    block_id_result_t new_block = allocate_block(state);
    if (new_block.return_code != FS_OK) {
        // no free blocks, so must release i-node as an entry requires at least one block
        release_i_node(state, new_i_node_info.index);
        add_completion_entry(client, new_block.return_code, 0, 0, SIZE_MAX);
        return (i_node_result_t){-1, new_block.return_code};
    }
    
    // if it's a directory, need to zero the block so that all child entries are initially empty
    // if its a file this is unnecessary as reading uninitialised data is undefined behaviour
    if (is_directory) {
        zero_block(state->blocks[new_block.index].data);
    }
    
    state->i_node_table[parent_i_node_index].entry_size += 1;

    state->i_node_table[new_i_node_info.index].mode = IN_USE_BIT_SET | (is_directory << DIRECTORY_BIT_START) | (permissions << PERMISSION_BITS_START); // not deleted, in use, dir, permissions
    state->i_node_table[new_i_node_info.index].owner_id = client_id;
    state->i_node_table[new_i_node_info.index].block_indices[0] = new_block.index;
    state->i_node_table[new_i_node_info.index].entry_size = 0;
    state->i_node_table[new_i_node_info.index].blocks_used = 1;

    // if its a directory we will not later open it in this creation call, so return
    // if it's a file, we want to open it and return a file descriptor yet
    if (is_directory) {
        add_completion_entry(client, FS_OK, 0, 0, SIZE_MAX);
    }

    return new_i_node_info;
}


i_node_result_t create_entry(fs_state_t *state, client_t *client, unsigned char *path,
                             const uint32_t parent_i_node_index, const permissions_t permissions,
                             const uint8_t client_id, const bool is_directory) {
    // each path segment begins with /, and relative paths not allowed, so must start from root
    if (path[0] != '/') {
        add_completion_entry(client, FS_ERR_INVALID_PATH, 0, 0, SIZE_MAX);
        return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
    }
    // skip segment delimiter
    path = &path[1];
    i_node_t *parent_i_node = &state->i_node_table[parent_i_node_index];
    size_t *indirect_block_data = (size_t *)&state->blocks[parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (size_t i = 0; i < parent_i_node->blocks_used; i++) {
        size_t block_index;
        // get the block index that we are searching through
        if (i < DIRECT_BLOCKS_PER_INODE) {
            // the first 11 blocks are directly indexed in the i-node
            block_index = parent_i_node->block_indices[i];
        } else {
            // after that they are stored in the 12th block as an array of block indices
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)&state->blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            // unused entry
            if (child_entries[j].name[0] == '\0') {
                continue;
            }
            int32_t cmp_result = compare_names(path, child_entries[j].name);
            if (cmp_result == FULL_PATH_EQUAL) {
                add_completion_entry(client, FS_ERR_ALREADY_EXISTS, 0, 0, SIZE_MAX);
                return (i_node_result_t){-1, FS_ERR_ALREADY_EXISTS};
            // need to enter enter new subdir
            } else if (cmp_result == PATH_SEGMENT_EQUAL) {
                // skip past the matching segment
                while (*path != '/') {
                    path = &path[1];
                }
                if (state->i_node_table[child_entries[j].i_node_index].mode & IS_DIRECTORY_BIT_SET) {
                    if (!valid_permissions(&state->i_node_table[child_entries[j].i_node_index], client_id, PERM_EXECUTE)) {
                        add_completion_entry(client, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
                        return (i_node_result_t){-1, FS_ERR_PERMISSION};
                    }
                    // keep searching for the rest of the path in this subdirectory
                    return create_entry(state, client, path, child_entries[j].i_node_index,
                                        permissions, client_id, is_directory);
                } else {
                    // cannot add file below a file
                    add_completion_entry(client, FS_ERR_INVALID_PATH, 0, 0, SIZE_MAX);
                    return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
                }
            }
        }
    }
    // if we get here, then the path is valid and does not already exist, so we can add it in the current directory
    // if this is the root dir, any entry addition is allowed
    if (parent_i_node_index != ROOT_DIRECTORY_I_NODE_INDEX &&
        parent_i_node->owner_id != client_id &&
        !valid_permissions(parent_i_node, client_id, PERM_WRITE)) {
        add_completion_entry(client, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return (i_node_result_t){-1, FS_ERR_PERMISSION};
    }

    child_slot_and_block_result_t free_child_slot = get_free_child_slot(state, parent_i_node_index);
    if (free_child_slot.return_code != FS_OK) {
        add_completion_entry(client, free_child_slot.return_code, 0, 0, SIZE_MAX);
        return (i_node_result_t){-1, free_child_slot.return_code};
    }

    return add_entry(state, client, parent_i_node_index, path, permissions, client_id,
                     free_child_slot, is_directory);
}


void delete_entry_operation(fs_state_t *state, client_t *client, const uint8_t client_id, unsigned char *path) {
    i_node_result_t parent_i_node_index = get_i_node_index(state, path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_PARENT_I_NODE);
    if (parent_i_node_index.return_code != FS_OK) {
        add_completion_entry(client, parent_i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }
    i_node_t *parent_i_node_ptr = &state->i_node_table[parent_i_node_index.index];

    i_node_result_t i_node_index = get_i_node_index(state, path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }
    if (state->i_node_table[i_node_index.index].owner_id != client_id && !valid_permissions(&state->i_node_table[i_node_index.index], client_id, PERM_WRITE)) {
        add_completion_entry(client, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return;
    }
    // if it's already deleted, just return as successful (idempotent), it will be removed when the last file descriptor is closed
    if (state->i_node_table[i_node_index.index].mode & IS_DELETED_BIT_SET) {
        add_completion_entry(client, FS_OK, 0, 0, SIZE_MAX);
        return;
    }
    
    // remove entry from parent dir
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
    if ((size_t)(parent_i_node_ptr->entry_size / MAX_CHILD_ENTRIES_PER_BLOCK) + 1 < parent_i_node_ptr->blocks_used + 1) {
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
        add_completion_entry(client, res, 0, 0, SIZE_MAX);
    } else {
        // if its a file, only remove i-node when all fds to it are closed
        if (is_i_node_open_by_other_client(state, i_node_index.index, client_id)) {
            state->i_node_table[i_node_index.index].mode |= IS_DELETED_BIT_SET;
            add_completion_entry(client, FS_OK, 0, 0, SIZE_MAX);
            return;
        }

        release_i_node(state, i_node_index.index);
        if (is_i_node_open_by_client(state, i_node_index.index, client_id)) {
            fs_result_t res = close_file_by_i_node_index(state, client_id, i_node_index.index);
            add_completion_entry(client, res, 0, 0, SIZE_MAX);
        } else {
            add_completion_entry(client, FS_OK, 0, 0, SIZE_MAX);
        }
    }
}


void set_entry_permissions_operation(fs_state_t *state, client_t *client, const uint8_t client_id,
                                     const permissions_t permissions, unsigned char *path) {

    i_node_result_t i_node_index = get_i_node_index(state, path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }

    // only the owner can change permissions
    if (state->i_node_table[i_node_index.index].owner_id != client_id) {
        add_completion_entry(client, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return;
    }

    // clear old permissions and set new ones, leaving other mode bits unchanged
    const uint8_t perm_mask = (uint8_t)(0b111u << PERMISSION_BITS_START);
    state->i_node_table[i_node_index.index].mode = (uint8_t)((state->i_node_table[i_node_index.index].mode & ~perm_mask) |
                                                      ((uint8_t)permissions << PERMISSION_BITS_START));

    add_completion_entry(client, FS_OK, 0, 0, SIZE_MAX);
}


void get_entry_permissions_operation(fs_state_t *state, client_t *client, const uint8_t client_id,
                                     unsigned char *path) {

    i_node_result_t i_node_index = get_i_node_index(state, path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }

    uint8_t permissions = (state->i_node_table[i_node_index.index].mode >> PERMISSION_BITS_START) & 0b111;
    add_completion_entry(client, FS_OK, permissions, 0, SIZE_MAX);
}


void get_entry_size_operation(fs_state_t *state, client_t *client, const uint8_t client_id, unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(state, path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }

    add_completion_entry(client, FS_OK, state->i_node_table[i_node_index.index].entry_size, 0, SIZE_MAX);
}


void entry_exists_operation(fs_state_t *state, client_t *client, const uint8_t client_id, unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(state, path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client, FS_OK, false, 0, SIZE_MAX);
        return;
    }

    add_completion_entry(client, FS_OK, true, 0, SIZE_MAX);
}


void list_directory_operation(fs_state_t *state, client_t *client, const uint8_t client_id, unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(state, path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }

    i_node_t *dir_i_node = &state->i_node_table[i_node_index.index];
    if (!(dir_i_node->mode & IS_DIRECTORY_BIT_SET)) {
        add_completion_entry(client, FS_ERR_INVALID_PATH, 0, 0, SIZE_MAX);
        return;
    }

    if (!valid_permissions(dir_i_node, client_id, PERM_READ)) {
        add_completion_entry(client, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return;
    }

    const size_t buffer_index = get_free_buffer(client->completion_buffer_table);
    if (buffer_index == SIZE_MAX) {
        add_completion_entry(client, FS_ERROR_NO_FREE_COMPLETION_BUFFERS, 0, 0, SIZE_MAX);
        return;
    }

    uint8_t *client_buffer_data = (uint8_t *)&client->completion_buffers[buffer_index];
    size_t *indirect_block_data = (size_t *)&state->blocks[dir_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    size_t chars_written = 0;
    for (size_t i = 0; i < dir_i_node->blocks_used; i++) {
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

            chars_written += copy_string_from_buffer(child_entries[j].name, &client_buffer_data[chars_written], max_amount_to_copy);

            // truncate buffer
            if (chars_written >= CLIENT_BUFFER_SIZE - 1) {
                client_buffer_data[chars_written - 4] = '.';
                client_buffer_data[chars_written - 3] = '.';
                client_buffer_data[chars_written - 2] = '.';
                client_buffer_data[chars_written - 1] = '\n';
                break;
            }

            // add newline after each entry
            client_buffer_data[chars_written] = '\n';
            chars_written += 1;
        }
    }

    client_buffer_data[chars_written] = '\0';
    add_completion_entry(client, FS_OK, 0, 0, buffer_index);
}

// ------------------------------ File operation functions ------------------------------- //

void open_file_operation(fs_state_t *state, client_t *client, const uint8_t client_id,
                         const file_open_operations_t requested_operations, unsigned char *path) {

    i_node_result_t i_node_index = get_i_node_index(state, path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);

    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }

    if (state->i_node_table[i_node_index.index].mode & IS_DIRECTORY_BIT_SET) {
        add_completion_entry(client, FS_ERR_INVALID_PATH, 0, 0, SIZE_MAX);
        return;
    }

    file_id_and_cursor_result_t fd = add_i_node_to_fd_table(state, client_id, i_node_index.index, requested_operations);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client, fd.return_code, 0, 0, SIZE_MAX);
        return;
    }
    
    add_completion_entry(client, FS_OK, fd.file_id, fd.cursor_position, SIZE_MAX);
}


void close_file_operation(fs_state_t *state, client_t *client, const uint8_t client_id,
                          const uint32_t file_descriptor_index) {

    file_descriptor_result_t fd = get_file_descriptor(state, client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client, fd.return_code, 0, 0, SIZE_MAX);
        return;
    }

    uint32_t i_node_index = fd.descriptor->i_node_index;
    fd.descriptor->i_node_index = -1;
    fd.descriptor->cursor_position = 0;
    fd.descriptor->valid_operations = 0;
    // if the i-node is marked as deleted and this was the last fd to it, we can now release the i-node and its blocks
    if (!is_i_node_open(state, i_node_index) && state->i_node_table[i_node_index].mode & IS_DELETED_BIT_SET) {
        release_i_node(state, i_node_index);
        add_completion_entry(client, FS_OK, 0, 0, SIZE_MAX);
        return;
    }

    add_completion_entry(client, FS_OK, 0, 0, SIZE_MAX);
}


void read_file_operation(fs_state_t *state, client_t *client, const uint8_t client_id,
                         const uint32_t file_descriptor_index, const size_t length) {

    file_descriptor_result_t fd = get_file_descriptor(state, client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client, fd.return_code, 0, 0, SIZE_MAX);
        return;
    }

    if (!(fd.descriptor->valid_operations & PERM_READ)) {
        add_completion_entry(client, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return;
    }
    i_node_t *i_node = &state->i_node_table[fd.descriptor->i_node_index];

    // if trying to read past end of file, just read until end of file and return an out of bounds error code to indicate this
    size_t bytes_to_read = length;
    fs_result_t return_code = FS_OK;
    if (fd.descriptor->cursor_position + length > i_node->entry_size) {
        bytes_to_read = i_node->entry_size - fd.descriptor->cursor_position;
        return_code = FS_ERR_OUT_OF_BOUNDS;
    }

    const size_t buffer_index = get_free_buffer(client->completion_buffer_table);
    if (buffer_index == SIZE_MAX) {
        add_completion_entry(client, FS_ERROR_NO_FREE_COMPLETION_BUFFERS, 0, 0, SIZE_MAX);
        return;
    }

    uint8_t *client_buffer_data = (uint8_t *)&client->completion_buffers[buffer_index];
    // to calculate bytes read
    size_t cursor_before = fd.descriptor->cursor_position;
    fs_result_t rc = copy_bytes_i_node(state, i_node, client_buffer_data, bytes_to_read, fd.descriptor, READ);
    if (rc != FS_OK) {
        add_completion_entry(client, rc, 0, 0, buffer_index);
        return;
    }

    add_completion_entry(client, return_code, fd.descriptor->cursor_position - cursor_before,
                         fd.descriptor->cursor_position, buffer_index);
}


void write_file_operation(fs_state_t *state, client_t *client, const uint8_t client_id,
                          const uint32_t file_descriptor_index, const size_t length,
                          const size_t submission_buffer_index) {

    file_descriptor_result_t fd = get_file_descriptor(state, client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client, fd.return_code, 0, 0, SIZE_MAX);
        return;
    }

    if (!(fd.descriptor->valid_operations & PERM_WRITE)) {
        add_completion_entry(client, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return;
    }
    i_node_t *i_node = &state->i_node_table[fd.descriptor->i_node_index];

    // if trying to write past max file size, just write until max file size and return an error code to indicate this
    size_t bytes_to_write = length;
    fs_result_t return_code = FS_OK;
    if (bytes_to_write + fd.descriptor->cursor_position >= MAX_BLOCKS_PER_FILE * BLOCK_SIZE) {
        return_code = FS_ERR_MAX_FILE_SIZE_REACHED;
        bytes_to_write = MAX_BLOCKS_PER_FILE * BLOCK_SIZE - fd.descriptor->cursor_position - 1;
    }

    size_t cursor_before = fd.descriptor->cursor_position;
    uint8_t *client_buffer_data = (uint8_t *)&client->submission_buffers[submission_buffer_index];
    fs_result_t rc = copy_bytes_i_node(state, i_node, client_buffer_data, bytes_to_write, fd.descriptor, WRITE);
    if (rc != FS_OK) {
        add_completion_entry(client, rc, 0, 0, SIZE_MAX);
        return;
    }

    add_completion_entry(client, return_code, fd.descriptor->cursor_position - cursor_before,
                         fd.descriptor->cursor_position, SIZE_MAX);
}


void seek_file_operation(fs_state_t *state, client_t *client, const uint8_t client_id,
                         const uint32_t file_descriptor_index, const size_t position) {

    file_descriptor_result_t fd = get_file_descriptor(state, client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client, fd.return_code, 0, 0, SIZE_MAX);
        return;
    }

    if (position > state->i_node_table[fd.descriptor->i_node_index].entry_size) {
        add_completion_entry(client, FS_ERR_OUT_OF_BOUNDS, 0, 0, SIZE_MAX);
        return;
    }
    
    fd.descriptor->cursor_position = position;
    add_completion_entry(client, FS_OK, 0, 0, SIZE_MAX);
}