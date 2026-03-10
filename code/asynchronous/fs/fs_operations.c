#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../debug_output.h"

#include "include/fs_buffer_manager.h"
#include "include/fs_shared.h"
#include "include/fs_internal.h"
#include "include/fs_block_manager.h"
#include "include/fs_block_data_manager.h"
#include "include/fs_i_node_manager.h"
#include "include/fs_directory_manager.h"
#include "include/fs_file_table_manager.h"
#include "include/fs_queue_manager_server.h"
#include "include/fs_utils.h"
#include "include/fs_state.h"

// ------------------------------ Directory entry management functions ------------------------------- //

i_node_result_t create_entry(unsigned char *path, const uint32_t parent_i_node_index,
                             const permissions_t permissions, const uint8_t client_id,
                             const bool is_directory) {
    microkit_debug_puts(OUTPUT_VERBOSITY, "entering dir ");
    microkit_debug_puts(OUTPUT_VERBOSITY, path);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    if (path[0] != '/') {
        add_completion_entry(client_id, FS_ERR_INVALID_PATH, 0, 0, SIZE_MAX);
        return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
    }
    path = &path[1];
    microkit_debug_puts(OUTPUT_VERBOSITY, "entering dir ");
    microkit_debug_puts(OUTPUT_VERBOSITY, path);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    i_node_t *parent_i_node = &i_node_table[parent_i_node_index];
    size_t *indirect_block_data = (size_t *)&blocks[parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (size_t i = 0; i < parent_i_node->blocks_used; i++) {
        size_t block_index;
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
            microkit_debug_puts(OUTPUT_VERBOSITY, "comparing to ");
            microkit_debug_puts(OUTPUT_VERBOSITY, child_entries[j].name);
            microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
            int32_t cmp_result = compare_names(path, child_entries[j].name);
            if (cmp_result == FULL_PATH_EQUAL) {
                add_completion_entry(client_id, FS_ERR_ALREADY_EXISTS, 0, 0, SIZE_MAX);
                return (i_node_result_t){-1, FS_ERR_ALREADY_EXISTS};
            } else if (cmp_result == PATH_SEGMENT_EQUAL) {
                while (*path != '/') {
                    path = &path[1];
                }
                if (i_node_table[child_entries[j].i_node_index].mode & IS_DIRECTORY_BIT_SET) {
                    if (!valid_permissions(&i_node_table[child_entries[j].i_node_index], client_id, PERM_EXECUTE)) {
                        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
                        return (i_node_result_t){-1, FS_ERR_PERMISSION};
                    }
                    return create_entry(path, child_entries[j].i_node_index, permissions, client_id,
                                        is_directory);
                } else {
                    add_completion_entry(client_id, FS_ERR_INVALID_PATH, 0, 0, SIZE_MAX);
                    return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
                }
            }
        }
    }

    if (parent_i_node_index != ROOT_DIRECTORY_I_NODE_INDEX &&
        parent_i_node->owner_id != client_id &&
        !valid_permissions(parent_i_node, client_id, PERM_WRITE)) {
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return (i_node_result_t){-1, FS_ERR_PERMISSION};
    }

    child_slot_and_block_result_t slot_info = get_free_child_slot(parent_i_node_index);
    microkit_debug_puts(OUTPUT_VERBOSITY, "child to root: ");
    microkit_debug_put32(OUTPUT_VERBOSITY, slot_info.entry_index);
    microkit_debug_putc(OUTPUT_VERBOSITY, '\n');
    if (slot_info.return_code != FS_OK) {
        add_completion_entry(client_id, slot_info.return_code, 0, 0, SIZE_MAX);
        return (i_node_result_t){-1, slot_info.return_code};
    }
    return add_entry(parent_i_node_index, path, permissions, client_id, slot_info.block_index,
                     slot_info.entry_index, is_directory);
}


void delete_entry_operation(const uint8_t client_id, unsigned char *path) {
    i_node_result_t parent_i_node = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_PARENT_I_NODE);
    if (parent_i_node.return_code != FS_OK) {
        add_completion_entry(client_id, parent_i_node.return_code, 0, 0, SIZE_MAX);
        return;
    }
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }
    if (i_node_table[i_node_index.index].owner_id != client_id && !valid_permissions(&i_node_table[i_node_index.index], client_id, PERM_WRITE)) {
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return;
    }
    if (i_node_table[i_node_index.index].mode & IS_DELETED_BIT_SET) {
        add_completion_entry(client_id, FS_OK, 0, 0, SIZE_MAX);
        return;
    }
    i_node_t *parent_i_node_ptr = &i_node_table[parent_i_node.index];
    size_t *indirect_block_data = (size_t *)&blocks[parent_i_node_ptr->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (size_t i = 0; i < parent_i_node_ptr->blocks_used; i++) {
        size_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node_ptr->block_indices[i];
        } else {
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)&blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].i_node_index == i_node_index.index) {
                child_entries[j].name[0] = '\0';
                parent_i_node_ptr->entry_size -= 1;
                break;
            }
        }
    }
    microkit_debug_puts(OUTPUT_VERBOSITY, "checking if can free block\n");
    microkit_debug_puts(OUTPUT_VERBOSITY, "entry size: ");
    microkit_debug_put32(OUTPUT_VERBOSITY, (int)(parent_i_node_ptr->entry_size / MAX_CHILD_ENTRIES_PER_BLOCK) + 1);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\nblocks used: ");
    microkit_debug_put32(OUTPUT_VERBOSITY, parent_i_node_ptr->blocks_used);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    if ((size_t)(parent_i_node_ptr->entry_size / MAX_CHILD_ENTRIES_PER_BLOCK) + 1 < parent_i_node_ptr->blocks_used) {
        defragment_directory(parent_i_node_ptr);
        size_t block_to_free_index = parent_i_node_ptr->blocks_used - 1;
        size_t block_index;
        if (block_to_free_index < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node_ptr->block_indices[block_to_free_index];
            parent_i_node_ptr->block_indices[block_to_free_index] = 0;
        } else {
            block_index = indirect_block_data[block_to_free_index - DIRECT_BLOCKS_PER_INODE];
            indirect_block_data[block_to_free_index - DIRECT_BLOCKS_PER_INODE] = 0;
        }
        release_block(block_index);
        parent_i_node_ptr->blocks_used -= 1;
    }
    if (is_i_node_open(i_node_index.index)) {
        i_node_table[i_node_index.index].mode |= IS_DELETED_BIT_SET;
        add_completion_entry(client_id, FS_OK, 0, 0, SIZE_MAX);
        return;
    }
    if (i_node_table[i_node_index.index].mode & IS_DIRECTORY_BIT_SET) {
        fs_result_t res = delete_directory_contents(i_node_index.index);
        release_i_node(i_node_index.index);
        add_completion_entry(client_id, res, 0, 0, SIZE_MAX);
    } else {
        microkit_debug_puts(OUTPUT_VERBOSITY, "releasing i node\n");
        release_i_node(i_node_index.index);
        microkit_debug_puts(OUTPUT_VERBOSITY, "closing file\n");
        if (is_i_node_open(i_node_index.index)) {
            fs_result_t res = close_file_by_i_node_index(client_id, i_node_index.index);
            add_completion_entry(client_id, res, 0, 0, SIZE_MAX);
        } else {
            add_completion_entry(client_id, FS_OK, 0, 0, SIZE_MAX);
        }
    }
}


void set_entry_permissions_operation(const uint8_t client_id, const permissions_t permissions,
                                     unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }
    if (i_node_table[i_node_index.index].owner_id != client_id) {
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return;
    }
    const uint8_t perm_mask = (uint8_t)(0b111u << PERMISSION_BITS_START);
    i_node_table[i_node_index.index].mode = (uint8_t)((i_node_table[i_node_index.index].mode & ~perm_mask) |
                                                      ((uint8_t)permissions << PERMISSION_BITS_START));
    add_completion_entry(client_id, FS_OK, 0, 0, SIZE_MAX);
}


void get_entry_permissions_operation(const uint8_t client_id, unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }
    uint8_t permissions = (i_node_table[i_node_index.index].mode >> PERMISSION_BITS_START) & 0b111;
    add_completion_entry(client_id, FS_OK, permissions, 0, SIZE_MAX);
}


void get_entry_size_operation(const uint8_t client_id, unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }
    add_completion_entry(client_id, FS_OK, i_node_table[i_node_index.index].entry_size, 0, SIZE_MAX);
}


void entry_exists_operation(const uint8_t client_id, unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, FS_OK, 0, 0, SIZE_MAX);
        return;
    }
    add_completion_entry(client_id, FS_OK, 1, 0, SIZE_MAX);
}


void list_directory_operation(const uint8_t client_id, unsigned char *path) {
    microkit_debug_puts(OUTPUT_VERBOSITY, "listing dir ");
    microkit_debug_puts(OUTPUT_VERBOSITY, path);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }
    i_node_t *dir_i_node = &i_node_table[i_node_index.index];
    if (!(dir_i_node->mode & IS_DIRECTORY_BIT_SET)) {
        add_completion_entry(client_id, FS_ERR_INVALID_PATH, 0, 0, SIZE_MAX);
        return;
    }
    if (!valid_permissions(dir_i_node, client_id, PERM_READ)) {
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return;
    }
    const size_t buffer_index = get_free_buffer(clients[client_id].completion_buffer_table);
    if (buffer_index == SIZE_MAX) {
        add_completion_entry(client_id, FS_ERROR_NO_FREE_COMPLETION_BUFFERS, 0, 0, SIZE_MAX);
        return;
    }
    uint8_t *client_buffer_data = (uint8_t *)&clients[client_id].completion_buffers[buffer_index];
    size_t *indirect_block_data = (size_t *)&blocks[dir_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    size_t chars_written = 0;
    for (size_t i = 0; i < dir_i_node->blocks_used; i++) {
        if (chars_written >= CLIENT_BUFFER_SIZE) {
            break;
        }
        size_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = dir_i_node->block_indices[i];
        } else {
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)&blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] != '\0') {
                const size_t max_amount_to_copy = (MAX_NAME_LENGTH > CLIENT_BUFFER_SIZE - chars_written) ? CLIENT_BUFFER_SIZE - chars_written : MAX_NAME_LENGTH;
                chars_written += copy_string_from_buffer(child_entries[j].name, &client_buffer_data[chars_written], max_amount_to_copy);
                if (chars_written >= CLIENT_BUFFER_SIZE) {
                    client_buffer_data[chars_written - 4] = '.';
                    client_buffer_data[chars_written - 3] = '.';
                    client_buffer_data[chars_written - 2] = '.';
                    client_buffer_data[chars_written - 1] = '\n';
                    break;
                }
                client_buffer_data[chars_written] = '\n';
                chars_written += 1;
            }

        }
    }
    client_buffer_data[chars_written] = '\0';
    add_completion_entry(client_id, FS_OK, 0, 0, buffer_index);
}

// ------------------------------ File operation functions ------------------------------- //

void open_file_operation(const uint8_t client_id, const file_open_operations_t requested_operations, unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        microkit_debug_puts(OUTPUT_VERBOSITY, "could not find i node\n");
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, SIZE_MAX);
        return;
    }
    if (i_node_table[i_node_index.index].mode & IS_DIRECTORY_BIT_SET) {
        microkit_debug_puts(OUTPUT_VERBOSITY, "tried to open directory as file\n");
        add_completion_entry(client_id, FS_ERR_INVALID_PATH, 0, 0, SIZE_MAX);
        return;
    }
    file_id_and_cursor_result_t fd = add_i_node_to_fd_table(client_id, i_node_index.index, requested_operations);
    if (fd.return_code != FS_OK) {
        microkit_debug_puts(OUTPUT_VERBOSITY, "could not add to fd table\n");
        add_completion_entry(client_id, fd.return_code, 0, 0, SIZE_MAX);
        return;
    }
    add_completion_entry(client_id, FS_OK, fd.file_id, fd.cursor_position, SIZE_MAX);
}


void close_file_operation(const uint8_t client_id, const uint32_t file_descriptor_index) {
    microkit_debug_puts(OUTPUT_VERBOSITY, "closing fd ");
    microkit_debug_put32(OUTPUT_VERBOSITY, file_descriptor_index);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client_id, fd.return_code, 0, 0, SIZE_MAX);
        return;
    }
    uint32_t i_node_index = fd.descriptor->i_node_index;
    fd.descriptor->i_node_index = -1;
    fd.descriptor->cursor_position = 0;
    fd.descriptor->valid_operations = 0;
    if (!is_i_node_open(i_node_index) && i_node_table[i_node_index].mode & IS_DELETED_BIT_SET) {
        microkit_debug_puts(OUTPUT_VERBOSITY, "releasing i node\n");
        release_i_node(i_node_index);
        add_completion_entry(client_id, FS_OK, 0, 0, SIZE_MAX);
        return;
    }
    add_completion_entry(client_id, FS_OK, 0, 0, SIZE_MAX);
}


void read_file_operation(const uint8_t client_id, const uint32_t file_descriptor_index, const size_t length) {
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client_id, fd.return_code, 0, 0, SIZE_MAX);
        return;
    }
    if (!(fd.descriptor->valid_operations & PERM_READ)) {
        microkit_debug_puts(OUTPUT_VERBOSITY, "no read perm\n");
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return;
    }
    fs_result_t return_code = FS_OK;
    i_node_t *i_node = &i_node_table[fd.descriptor->i_node_index];
    size_t bytes_to_read = length;
    if (fd.descriptor->cursor_position + length > i_node->entry_size) {
        bytes_to_read = i_node->entry_size - fd.descriptor->cursor_position;
        return_code = FS_ERR_OUT_OF_BOUNDS;
    }
    const size_t buffer_index = get_free_buffer((bool *)&clients[client_id].completion_buffer_table);
    if (buffer_index == SIZE_MAX) {
        add_completion_entry(client_id, FS_ERROR_NO_FREE_COMPLETION_BUFFERS, 0, 0, SIZE_MAX);
        return;
    }
    uint8_t *client_buffer_data = (uint8_t *)&clients[client_id].completion_buffers[buffer_index];
    size_t cursor_before = fd.descriptor->cursor_position;
    fs_result_t rc = copy_bytes_i_node(i_node, client_buffer_data, bytes_to_read, fd.descriptor, READ);
    if (rc != FS_OK) {
        add_completion_entry(client_id, rc, 0, 0, buffer_index);
        return;
    }
    add_completion_entry(client_id, return_code, fd.descriptor->cursor_position - cursor_before, fd.descriptor->cursor_position, buffer_index);
}


void write_file_operation(const uint8_t client_id, const uint32_t file_descriptor_index, const size_t length,
                          const size_t submission_buffer_index) {
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client_id, fd.return_code, 0, 0, SIZE_MAX);
        return;
    }
    if (!(fd.descriptor->valid_operations & PERM_WRITE)) {
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, SIZE_MAX);
        return;
    }
    fs_result_t return_code = FS_OK;
    i_node_t *i_node = &i_node_table[fd.descriptor->i_node_index];
    size_t bytes_to_write = length;
    if (bytes_to_write + fd.descriptor->cursor_position >= MAX_BLOCKS_PER_FILE * BLOCK_SIZE) {
        return_code = FS_ERR_MAX_FILE_SIZE_REACHED;
        bytes_to_write = MAX_BLOCKS_PER_FILE * BLOCK_SIZE - fd.descriptor->cursor_position - 1;
    }
    microkit_debug_puts(OUTPUT_VERBOSITY, "writing ");
    microkit_debug_put32(OUTPUT_VERBOSITY, bytes_to_write);
    microkit_debug_puts(OUTPUT_VERBOSITY, " bytes\n");
    size_t cursor_before = fd.descriptor->cursor_position;
    uint8_t *client_buffer_data = (uint8_t *)&clients[client_id].submission_buffers[submission_buffer_index];
    fs_result_t rc = copy_bytes_i_node(i_node, client_buffer_data, bytes_to_write, fd.descriptor, WRITE);
    microkit_debug_puts(OUTPUT_VERBOSITY, "write complete\n");
    if (rc != FS_OK) {
        add_completion_entry(client_id, rc, 0, 0, SIZE_MAX);
        return;
    }
    add_completion_entry(client_id, return_code, fd.descriptor->cursor_position - cursor_before, fd.descriptor->cursor_position, SIZE_MAX);
}


void seek_file_operation(const uint8_t client_id, const uint32_t file_descriptor_index,
                         const size_t position) {
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client_id, fd.return_code, 0, 0, SIZE_MAX);
        return;
    }
    if (position > i_node_table[fd.descriptor->i_node_index].entry_size) {
        add_completion_entry(client_id, FS_ERR_OUT_OF_BOUNDS, 0, 0, SIZE_MAX);
        return;
    }
    fd.descriptor->cursor_position = position;
    add_completion_entry(client_id, FS_OK, 0, 0, SIZE_MAX);
}