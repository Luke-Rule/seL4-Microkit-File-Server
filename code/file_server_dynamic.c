// ----------------------------------------------------------------------- //
// ------------------------ MicroKit File Server ------------------------- //
// ----------------------------------------------------------------------- //


// ------------------------------ Includes ------------------------------- //

#include <microkit.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "definitions.h"
#include "utils.c"

// ------------------------------ Definitions ----------------------------- //

// System parameters
#define NUMBER_OF_CLIENTS 1

// Client memory
#define CLIENT_BUFFER_SIZE 0x40000
#define CLIENT_BUFFER_BASE(client_id) ((uintptr_t)client_buffers + (uintptr_t)(client_id * CLIENT_BUFFER_SIZE))

// File server memory
#define BLOCK_SIZE 0x40000
#define BLOCK_DATA_SIZE 0x1F3FC000
#define MAX_NUMBER_OF_BLOCKS (BLOCK_DATA_SIZE / BLOCK_SIZE)
#define DIRECT_BLOCKS_PER_INODE 12
#define BLOCK_ADDRESS(block_index) (uint32_t *)(blocks_base + (block_index * BLOCK_SIZE))
#define MAX_OPEN_FILES_PER_CLIENT 64
#define INODE_TABLE_SIZE 0x60000
#define MAX_INODES (INODE_TABLE_SIZE / sizeof(i_node_t))
#define FILE_DESCRIPTOR_ENTRY_SIZE sizeof(struct file_descriptor)
#define FILE_DESCRIPTOR_OFFSET(client_id, file_index) (file_descriptor_table_base + client_id * MAX_OPEN_FILES_PER_CLIENT + file_index)
#define MAX_CHILD_ENTRIES_PER_BLOCK (BLOCK_SIZE / sizeof(child_entry_t))
#define MAX_BLOCK_POINTERS_PER_INDIRECT_BLOCK (BLOCK_SIZE / sizeof(uint32_t))
#define MAX_BLOCKS_PER_FILE (DIRECT_BLOCKS_PER_INODE - 1 + MAX_BLOCK_POINTERS_PER_INDIRECT_BLOCK)
#define NUMBER_OF_BLOCKS(entry_size) (entry_size / BLOCK_SIZE + 1)
#define MAX_CHILDREN_PER_DIRECTORY (MAX_BLOCKS_PER_FILE * MAX_CHILD_ENTRIES_PER_BLOCK)

// ------------------------------ Globals ------------------------------- //

/*
TODO:
- Permissions
- Modify file operations to use i-nodes 
- Modift file operations to use file descriptors
*/

struct file_descriptor
{
    uint32_t i_node_index;
    uint32_t cursor_position;
    uint8_t valid_operatons;
} typedef file_descriptor_t;

struct file_descriptor_result
{
    file_descriptor_t *descriptor;
    int return_code;
} typedef file_descriptor_result_t;

struct file_index_and_cursor_result
{
    uint32_t file_index;
    uint32_t cursor_position;
    int return_code;
} typedef file_index_and_cursor_result_t;

struct i_node
{
    uint8_t mode; // 3 for perm, 1 for dir, 1 for in use 
    uint8_t owner_id;
    uint32_t entry_size;
    uint32_t block_indices[DIRECT_BLOCKS_PER_INODE];
} typedef i_node_t;

struct i_node_result
{
    int32_t index;
    int return_code;
} typedef i_node_result_t;

struct child_entry
{
    unsigned char name[MAX_FILE_NAME_LENGTH];
    uint32_t i_node_index;
} typedef child_entry_t;

struct block_id_result
{
    uint32_t index;
    int return_code;
} typedef block_id_result_t;

struct block_search_result
{
    uint32_t i_node_block_index;
    uint32_t block_offset;
    uint32_t is_indirect;
} typedef block_search_result_t;

struct child_slot_and_block_result {
    uint32_t block_index;
    uint32_t entry_index;
    int return_code;
} typedef child_slot_and_block_result_t;

uintptr_t block_table_base;
uintptr_t blocks_base;
uintptr_t i_node_table_base;
uintptr_t file_descriptor_table_base;
uintptr_t lowest_client_buffer_base;

int8_t *block_table;
file_descriptor_t *file_descriptor_table;
i_node_t *i_node_table;
int8_t *client_buffers;

uint32_t free_block_count = MAX_NUMBER_OF_BLOCKS;


block_id_result_t allocate_block() {
    for (size_t i = 0; i < MAX_NUMBER_OF_BLOCKS; i++) {
        if (block_table[i] == 0) {
            block_table[i] = 1;
            free_block_count--;
            return (block_id_result_t){i, FS_OK};
        }
    }
    return (block_id_result_t){0, FS_ERR_NO_BLOCKS_REMAINING};
}


void release_block(const uint32_t block_index) {
    if (block_index < MAX_NUMBER_OF_BLOCKS && block_table[block_index] == 1) {
        block_table[block_index] = 0;
        free_block_count++;
    }
}


i_node_result_t allocate_i_node() {
    for (size_t i = 0; i < MAX_INODES; i++) {
        if ((i_node_table[i].mode & 0x1) == 0) {
            i_node_table[i].mode |= 0x1;
            return (i_node_result_t){i, FS_OK};
        }
    }
    return (i_node_result_t){0, FS_ERR_INODE_TABLE_FULL};
}


void release_i_node(const uint32_t i_node_index) {
    if (i_node_index < MAX_INODES) {
        i_node_table[i_node_index].mode = 0;
        for (size_t i = 0; i < DIRECT_BLOCKS_PER_INODE - 1; i++) {
            if (i_node_table[i_node_index].block_indices[i] != -1) {
                release_block(i_node_table[i_node_index].block_indices[i]);
            }
        }
        const uint32_t indirect_block_index = i_node_table[i_node_index].block_indices[DIRECT_BLOCKS_PER_INODE - 1];
        uint32_t *indirect_block = BLOCK_ADDRESS(indirect_block_index);
        for (size_t i = 0; i < NUMBER_OF_BLOCKS(i_node_table[i_node_index].entry_size) - DIRECT_BLOCKS_PER_INODE + 1; i++) {
            release_block(indirect_block[i]);
        }
        release_block(indirect_block_index);
    }
}


int compare_names(const unsigned char *name1, const unsigned char *name2) {
    for (size_t i = 0; i < MAX_FILE_NAME_LENGTH; i++) {
        if (name1[i] != name2[i]) {
            return FULL_PATH_NOT_EQUAL;
        }
        if (name1[i] == '/') {
            return PATH_SEGMENT_EQUAL;
        }
        if (name1[i] == '\0') {
            return FULL_PATH_EQUAL;
        }
    }
    return 0; 
}


int valid_permissions(i_node_t i_node, const uint8_t client_id, const permissions_t required) {
    if (i_node.owner_id == client_id) {
        return 1;
    }
    permissions_t dir_perm = (i_node.mode >> 2) & 0b111;
    if ((dir_perm & required) == required) {
        return 1;
    }
    return 0;
}


int valid_name(const unsigned char *name) {
    if (name[0] == '\0' || name[0] == '/') {
        return 0;
    }
    for (size_t i = 0; i < MAX_FILE_NAME_LENGTH; i++) {
        if (name[i] == '\0') {
            break;
        }
        if (name[i] == '/') {
            return 0;
        }
    }
    return 1;
}


i_node_result_t get_i_node(unsigned char *path, const uint32_t current_i_node_index, const uint8_t client_id, const int get_parent) {
    if (path[0] != '/') {
        return (i_node_result_t){NULL, FS_ERR_INVALID_PATH};
    }
    path = &path[1];
    i_node_t *current_i_node = &i_node_table[current_i_node_index];
    uint32_t *indirect_block = BLOCK_ADDRESS(current_i_node->block_indices[DIRECT_BLOCKS_PER_INODE - 1]);
    for (int i = 0; i < NUMBER_OF_BLOCKS(current_i_node->entry_size); i++) {
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE - 1) {
            block_index = current_i_node->block_indices[i];
        } else {
            block_index = indirect_block[i - DIRECT_BLOCKS_PER_INODE + 1];
        }
        child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] == '\0') {
                continue;
            }
            int cmp_result = compare_names(path, child_entries[j].name);
            if (cmp_result == FULL_PATH_EQUAL) {
                if (get_parent) {
                    return (i_node_result_t){&i_node_table[current_i_node_index], FS_OK};
                }
                return (i_node_result_t){&i_node_table[child_entries[j].i_node_index], FS_OK};
            } else if (cmp_result == PATH_SEGMENT_EQUAL) {
                while (*path != '/') {
                    path = &path[1];
                }
                if (i_node_table[child_entries[j].i_node_index].mode & 0b10) {
                    if (!valid_permissions(i_node_table[child_entries[j].i_node_index], client_id, PERM_EXECUTE)) {
                        return (i_node_result_t){NULL, FS_ERR_PERMISSION};
                    }
                    return get_i_node(path, child_entries[j].i_node_index, client_id, get_parent);
                } else {
                    return (i_node_result_t){NULL, FS_ERR_INVALID_PATH};
                }
            }
        }
    }
    return (i_node_result_t){NULL, FS_ERR_NOT_FOUND};
}


i_node_result_t add_entry(const uint32_t parent_i_node, unsigned char *name, const permissions_t permissions, const uint8_t client_id, const uint32_t block_index, const uint32_t entry_index, const int is_directory) {
    if (!valid_name(name)) {
        return (i_node_result_t){NULL, FS_ERR_INVALID_PATH};
    }
    i_node_result_t new_i_node_info = allocate_i_node();
    if (new_i_node_info.return_code != FS_OK) {
        return new_i_node_info;
    }
    i_node_t *current_i_node = &i_node_table[parent_i_node];
    child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
    copy_string_from_buffer(name, child_entries[entry_index].name, MAX_FILE_NAME_LENGTH);
    child_entries[entry_index].i_node_index = new_i_node_info.index;

    block_id_result_t new_block = allocate_block();
    if (new_block.return_code != FS_OK) {
        release_i_node(new_i_node_info.index);
        return (i_node_result_t){NULL, new_block.return_code};
    }

    current_i_node->entry_size += 1;

    i_node_table[new_i_node_info.index].mode = is_directory | 0b0010 | (permissions << 2); // in use, dir, permissions
    i_node_table[new_i_node_info.index].owner_id = client_id;
    i_node_table[new_i_node_info.index].block_indices[0] = new_block.index;
    i_node_table[new_i_node_info.index].entry_size = 0;

    return new_i_node_info;
}


child_slot_and_block_result_t get_free_child_slot(const uint32_t parent_i_node_index) {
    i_node_t *parent_i_node = &i_node_table[parent_i_node_index];
    uint32_t *indirect_block = BLOCK_ADDRESS(parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE - 1]);
    for (int i = 0; i < NUMBER_OF_BLOCKS(parent_i_node->entry_size); i++) {
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node->block_indices[i];
        } else {
            block_index = indirect_block[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] == '\0') {
                return (child_slot_and_block_result_t){block_index, j, FS_OK};
            }
        }
    }
    block_id_result_t new_block = allocate_block();
    if (new_block.return_code != FS_OK) {
        return (child_slot_and_block_result_t){0, 0, new_block.return_code};
    }
    if (NUMBER_OF_BLOCKS(parent_i_node->entry_size) < DIRECT_BLOCKS_PER_INODE - 1) {
        parent_i_node->block_indices[NUMBER_OF_BLOCKS(parent_i_node->entry_size)] = new_block.index;
    } else {
        if (NUMBER_OF_BLOCKS(parent_i_node->entry_size) == DIRECT_BLOCKS_PER_INODE - 1) {
            block_id_result_t indirect_block = allocate_block();
            if (indirect_block.return_code != FS_OK) {
                release_block(new_block.index);
                return (child_slot_and_block_result_t){0, 0, indirect_block.return_code};
            }
            parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE - 1] = indirect_block.index;
        }
        uint32_t *indirect_block = BLOCK_ADDRESS(parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE - 1]);
        indirect_block[NUMBER_OF_BLOCKS(parent_i_node->entry_size) - DIRECT_BLOCKS_PER_INODE] = new_block.index;
    }
    return (child_slot_and_block_result_t){new_block.index, 0, FS_OK};
}


file_descriptor_result_t get_file_descriptor(const uint32_t client_id, const uint32_t file_index) {
    if (file_index >= MAX_OPEN_FILES_PER_CLIENT) {
        return (file_descriptor_result_t){NULL, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND};
    }
    return (file_descriptor_result_t){&file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + file_index], FS_OK};
}


file_index_and_cursor_result_t add_i_node_to_fd_table(const uint32_t client_id, const uint32_t i_node_index, const uint8_t requested_operations) {
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index == i_node_index) {
            if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operatons != requested_operations) {
                if (!valid_permissions(i_node_table[i_node_index], client_id, requested_operations)) {
                    return (file_index_and_cursor_result_t){-1, -1, FS_ERR_PERMISSION};
                }
                file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operatons = requested_operations;
            }
            return (file_index_and_cursor_result_t){i, file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].cursor_position, FS_OK};
        }
    }
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index == -1) {
            if (!valid_permissions(i_node_table[i_node_index], client_id, requested_operations)) {
                return (file_index_and_cursor_result_t){-1, -1, FS_ERR_PERMISSION};
            }
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operatons = requested_operations;
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index = i_node_index;
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].cursor_position = 0;
            return (file_index_and_cursor_result_t){i, 0, FS_OK};
        }
    }
    return (file_index_and_cursor_result_t){-1, -1, FS_ERR_MAX_OPEN_FILES_REACHED};
}


i_node_result_t create_entry(unsigned char *path, const uint32_t current_i_node_index, const permissions_t permissions, const uint8_t client_id, const int is_directory) {
    if (path[0] != '/') {
        return (i_node_result_t){NULL, FS_ERR_INVALID_PATH};
    }
    path = &path[1];
    i_node_t *current_i_node = &i_node_table[current_i_node_index];
    uint32_t *indirect_block = BLOCK_ADDRESS(current_i_node->block_indices[DIRECT_BLOCKS_PER_INODE - 1]);
    for (int i = 0; i < NUMBER_OF_BLOCKS(current_i_node->entry_size); i++) {
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = current_i_node->block_indices[i];
        } else {
            block_index = indirect_block[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] == '\0') {
                continue;
            }
            int cmp_result = compare_names(path, child_entries[j].name);
            if (cmp_result == FULL_PATH_EQUAL) {
                return (i_node_result_t){NULL, FS_ERR_ALREADY_EXISTS};
            } else if (cmp_result == PATH_SEGMENT_EQUAL) {
                while (*path != '/') {
                    path = &path[1];
                }
                if (i_node_table[child_entries[j].i_node_index].mode & 0b10) {
                    if (!valid_permissions(i_node_table[child_entries[j].i_node_index], client_id, PERM_EXECUTE)) {
                        return (i_node_result_t){NULL, FS_ERR_PERMISSION};
                    }
                    return create_entry(path, child_entries[j].i_node_index, permissions, client_id, is_directory);
                } else {
                    return (i_node_result_t){NULL, FS_ERR_INVALID_PATH};
                }
            } else {
                if (!valid_permissions(i_node_table[child_entries[j].i_node_index], client_id, PERM_WRITE)) {
                    return (i_node_result_t){NULL, FS_ERR_PERMISSION};
                }
                child_slot_and_block_result_t slot_info = get_free_child_slot(child_entries[j].i_node_index);
                if (slot_info.return_code != FS_OK) {
                    return (i_node_result_t){NULL, slot_info.return_code};
                }
                return add_entry(child_entries[j].i_node_index, &path[1], permissions, client_id, slot_info.block_index, slot_info.entry_index, is_directory);
            }
        }
    }
    return (i_node_result_t){NULL, FS_ERR_NOT_FOUND};
}


block_search_result_t get_inode_block_index_from_file_index(const uint32_t file_index) {
    uint32_t block_index = file_index / BLOCK_SIZE;
    uint32_t block_offset = file_index % BLOCK_SIZE;
    if (block_index < DIRECT_BLOCKS_PER_INODE - 1) {
        return (block_search_result_t){block_index, block_offset, 0};
    } else {
        return (block_search_result_t){DIRECT_BLOCKS_PER_INODE - block_index, block_offset, 1};
    }
}


fs_result_t copy_bytes_i_node(i_node_t *i_node, int8_t *client_buffer, size_t length, file_descriptor_t *fd, int rnw) {
    size_t buffer_index = 0;
    block_search_result_t block_info = get_inode_block_index_from_file_index(fd->cursor_position);
    uint32_t *indirect_block = BLOCK_ADDRESS(i_node->block_indices[DIRECT_BLOCKS_PER_INODE - 1]);
    while (length > 0) {
        uint32_t block_index;
        if (block_info.is_indirect) {
            block_index = indirect_block[block_info.i_node_block_index];
        } else {
            block_index = i_node->block_indices[block_info.i_node_block_index];
        }
        int8_t *block_data = (int8_t *)BLOCK_ADDRESS(block_index);
        size_t bytes_available_in_block = BLOCK_SIZE - block_info.block_offset;
        size_t bytes_this_iteration = (length < bytes_available_in_block) ? length : bytes_available_in_block;
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
        if (block_info.is_indirect) {
            block_info.i_node_block_index++;
        } else {
            if (block_info.i_node_block_index + 1 >= DIRECT_BLOCKS_PER_INODE - 1) {
                block_info.is_indirect = 1;
                block_info.i_node_block_index = 0;
            } else {
                block_info.i_node_block_index++;
            }
        }
        block_info.block_offset = 0;
        if (!rnw){
            if (NUMBER_OF_BLOCKS(i_node->entry_size) <= block_info.i_node_block_index) {
                block_id_result_t new_block = allocate_block();
                if (new_block.return_code != FS_OK) {
                    return FS_ERR_NO_BLOCKS_REMAINING;
                }
                if (block_info.is_indirect) {
                    indirect_block[block_info.i_node_block_index] = new_block.index;
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
    client_buffer[0] = buffer_index;
    return FS_OK;
}


fs_result_t open_file_operation(const uint32_t client_id, const uint8_t requested_operations) {
    unsigned char *path = (unsigned char *)CLIENT_BUFFER_BASE(client_id);
    i_node_result_t i_node = get_i_node(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, 0);
    if (i_node.index < FS_OK) {
        return i_node.index;
    }
    file_index_and_cursor_result_t fd = add_i_node_to_fd_table(client_id, i_node.index, requested_operations);
    if (fd.return_code != FS_OK) {
        return fd.return_code;
    }
    uint32_t *client_buffer = (uint32_t *)CLIENT_BUFFER_BASE(client_id);
    client_buffer[0] = fd.file_index;
    client_buffer[1] = 0;
    return FS_OK;
}


fs_result_t close_file_operation(const uint32_t client_id, const uint32_t file_descriptor_index) {
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        return fd.return_code;
    }
    fd.descriptor->i_node_index = -1;
    fd.descriptor->cursor_position = 0;
    fd.descriptor->valid_operatons = 0;
    return FS_OK;
}


fs_result_t read_file_operation(const uint32_t client_id, const uint32_t file_descriptor_index, const size_t length) {
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        return fd.return_code;
    }
    if (!(fd.descriptor->valid_operatons & PERM_READ)) {
        return FS_ERR_PERMISSION;
    }
    fs_result_t return_code = FS_OK;
    i_node_t *i_node = &i_node_table[fd.descriptor->i_node_index];
    size_t bytes_to_read = length;
    if (fd.descriptor->cursor_position + length > i_node->entry_size) {
        bytes_to_read = i_node->entry_size - fd.descriptor->cursor_position;
        return_code = FS_ERR_OUT_OF_BOUNDS;
    }
    int8_t *client_buffer = (int8_t *)CLIENT_BUFFER_BASE(client_id);
    copy_bytes_i_node(i_node, client_buffer, bytes_to_read, fd.descriptor, 1);
    return return_code;
}


fs_result_t write_file_operation(const uint32_t client_id, const uint32_t file_descriptor_index, size_t length) {
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        return fd.return_code;
    }
    if (!(fd.descriptor->valid_operatons & PERM_WRITE)) {
        return FS_ERR_PERMISSION;
    }
    fs_result_t return_code = FS_OK;
    i_node_t *i_node = &i_node_table[fd.descriptor->i_node_index];
    if (i_node->entry_size + length - fd.descriptor->cursor_position > MAX_BLOCKS_PER_FILE * BLOCK_SIZE) {
        return_code = FS_ERR_MAX_FILE_SIZE_REACHED;
        length = MAX_BLOCKS_PER_FILE * BLOCK_SIZE - (i_node->entry_size + length - fd.descriptor->cursor_position);
    }
    int8_t *client_buffer = (int8_t *)CLIENT_BUFFER_BASE(client_id);
    copy_bytes_i_node(i_node, client_buffer, length, fd.descriptor, 0);
    return return_code;
}


fs_result_t seek_file_operation(const uint32_t client_id, const uint32_t file_descriptor_index, const uint32_t position) {
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        return fd.return_code;
    }
    if (position > i_node_table[fd.descriptor->i_node_index].entry_size) {
        return FS_ERR_OUT_OF_BOUNDS;
    }
    fd.descriptor->cursor_position = position;
    return FS_OK;
}


fs_result_t delete_file_operation(const uint32_t client_id, unsigned char *path) {
    i_node_result_t i_node = get_i_node(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, 0);
    if (i_node.return_code != FS_OK) {
        return i_node.return_code;
    }
    close_file_operation(client_id, i_node.index);
    release_i_node(i_node.index);
    return FS_OK;
}


fs_result_t set_entry_permissions_file_operation(const uint32_t client_id, unsigned char *path, const permissions_t permissions) {
    i_node_result_t i_node = get_i_node(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, 0);
    if (i_node.return_code != FS_OK) {
        return i_node.return_code;
    }
    if (i_node_table[i_node.index].owner_id != client_id) {
        return FS_ERR_PERMISSION;
    }
    i_node_table[i_node.index].mode = (i_node_table[i_node.index].mode & 0b00011) | (permissions << 2);
    return FS_OK;
}


fs_result_t get_entry_permissions_file_operation(const uint32_t client_id, unsigned char *path) {
    i_node_result_t i_node = get_i_node(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, 0);
    if (i_node.return_code != FS_OK) {
        return i_node.return_code;
    }
    uint8_t permissions = (i_node_table[i_node.index].mode >> 2) & 0b111;
    uint32_t *client_buffer = (uint32_t *)CLIENT_BUFFER_BASE(client_id);
    client_buffer[0] = permissions;
    return FS_OK;
}


fs_result_t get_entry_size_file_operation(const uint32_t client_id, unsigned char *path) {
    i_node_result_t i_node = get_i_node(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, 0);
    if (i_node.return_code != FS_OK) {
        return i_node.return_code;
    }
    uint32_t entry_size = i_node_table[i_node.index].entry_size;
    uint32_t *client_buffer = (uint32_t *)CLIENT_BUFFER_BASE(client_id);
    client_buffer[0] = entry_size;
    return FS_OK;
}


fs_result_t entry_exists_operation(const uint32_t client_id, unsigned char *path) {
    i_node_result_t i_node = get_i_node(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, 0);
    if (i_node.return_code != FS_OK) {
        uint32_t *client_buffer = (uint32_t *)CLIENT_BUFFER_BASE(client_id);
        client_buffer[0] = 0;
        return FS_OK;
    }
    uint32_t *client_buffer = (uint32_t *)CLIENT_BUFFER_BASE(client_id);
    client_buffer[0] = 1;
    return FS_OK;
}


fs_result_t list_directory_operation(const uint32_t client_id, unsigned char *path) {
    i_node_result_t i_node = get_i_node(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, 0);
    if (i_node.return_code != FS_OK) {
        return i_node.return_code;
    }
    i_node_t *dir_i_node = &i_node_table[i_node.index];
    if (!(dir_i_node->mode & 0b10)) {
        return FS_ERR_INVALID_PATH;
    }
    if (!valid_permissions(*dir_i_node, client_id, PERM_READ)) {
        return FS_ERR_PERMISSION;
    }
    uint32_t *indirect_block = BLOCK_ADDRESS(dir_i_node->block_indices[DIRECT_BLOCKS_PER_INODE - 1]);
    int chars_written = 0;
    for (int i = 0; i < NUMBER_OF_BLOCKS(dir_i_node->entry_size); i++) {
        if (chars_written >= CLIENT_BUFFER_SIZE) {
            break;
        }
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = dir_i_node->block_indices[i];
        } else {
            block_index = indirect_block[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] != '\0') {
                chars_written += copy_string_from_buffer(child_entries[j].name, &((unsigned char *)CLIENT_BUFFER_BASE(client_id))[chars_written], (MAX_FILE_NAME_LENGTH > CLIENT_BUFFER_SIZE - chars_written) ? CLIENT_BUFFER_SIZE - chars_written : MAX_FILE_NAME_LENGTH);
            }
        }
    }
    return FS_OK;
}


fs_result_t rename_entry_operation(const uint32_t client_id, unsigned char *path, unsigned char *new_name) {
    if (!valid_name(new_name)) {
        return FS_ERR_INVALID_PATH;
    }
    if (compare_names(path, new_name) == FULL_PATH_EQUAL) {
        return FS_OK;
    }
    i_node_result_t parent_i_node = get_i_node(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, 1);
    if (parent_i_node.return_code != FS_OK) {
        return parent_i_node.return_code;
    }
    i_node_t *dir_i_node = &i_node_table[parent_i_node.index];
    if (!(dir_i_node->mode & 0b10)) {
        return FS_ERR_INVALID_PATH;
    }
    if (!valid_permissions(*dir_i_node, client_id, PERM_WRITE)) {
        return FS_ERR_PERMISSION;
    }
    uint32_t *indirect_block = BLOCK_ADDRESS(dir_i_node->block_indices[DIRECT_BLOCKS_PER_INODE - 1]);
    for (int i = 0; i < NUMBER_OF_BLOCKS(dir_i_node->entry_size); i++) {
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = dir_i_node->block_indices[i];
        } else {
            block_index = indirect_block[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] == '\0') {
                continue;
            }
            if (compare_names(path, child_entries[j].name)) {
                copy_string_from_buffer(new_name, child_entries[j].name, MAX_FILE_NAME_LENGTH);
                return FS_OK;
            }
        }
    }
    return FS_ERR_UNSPECIFIED_ERROR;
}


fs_result_t copy_entry_operation(const uint32_t client_id, unsigned char *source_path, unsigned char *dest_dir, unsigned char *dest_name) {
    if (compare_names(source_path, dest_dir) == FULL_PATH_EQUAL) {
        return FS_ERR_INVALID_PATH;
    }
    i_node_result_t source_i_node = get_i_node(source_path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, 0);
    if (source_i_node.return_code != FS_OK) {
        return source_i_node.return_code;
    }
    if (!valid_permissions(i_node_table[source_i_node.index], client_id, PERM_READ)) {
        return FS_ERR_PERMISSION;
    }
    i_node_result_t dest_parent_i_node = get_i_node(dest_dir, ROOT_DIRECTORY_I_NODE_INDEX, client_id, 1);
    if (dest_parent_i_node.return_code != FS_OK) {
        return dest_parent_i_node.return_code;
    }
    if (!valid_permissions(i_node_table[dest_parent_i_node.index], client_id, PERM_WRITE)) {
        return FS_ERR_PERMISSION;
    }
    if (!(i_node_table[source_i_node.index].mode & 0b10)) {
        return FS_ERR_INVALID_PATH;
    }
    child_slot_and_block_result_t slot_info = get_free_child_slot(dest_parent_i_node.index);
    if (slot_info.return_code != FS_OK) {
        return slot_info.return_code;
    }
    i_node_result_t new_i_node = add_entry(dest_parent_i_node.index, dest_name, (i_node_table[source_i_node.index].mode >> 2) & 0b111, client_id, slot_info.block_index, slot_info.entry_index, ((i_node_table[source_i_node.index].mode & 0b10) >> 1) & 0b1);
    if (new_i_node.return_code != FS_OK) {
        return new_i_node.return_code;
    }
    // copy data from source to new i-node
    i_node_t *source_node = &i_node_table[source_i_node.index];
    i_node_t *dest_node = &i_node_table[new_i_node.index];
    dest_node->entry_size = source_node->entry_size;
    for (size_t i = 0; i < DIRECT_BLOCKS_PER_INODE - 1; i++) {
        if (source_node->block_indices[i] != -1) {
            block_id_result_t new_block = allocate_block();
            if (new_block.return_code != FS_OK) {
                return new_block.return_code;
            }
            dest_node->block_indices[i] = new_block.index;
            int8_t *source_block = (int8_t *)BLOCK_ADDRESS(source_node->block_indices[i]);
            int8_t *dest_block = (int8_t *)BLOCK_ADDRESS(new_block.index);
            copy_data_from_buffer(source_block, dest_block, BLOCK_SIZE);
        }
    }
    const uint32_t indirect_block_index = source_node->block_indices[DIRECT_BLOCKS_PER_INODE - 1];
    if (indirect_block_index != -1) {
        block_id_result_t new_indirect_block = allocate_block();
        if (new_indirect_block.return_code != FS_OK) {
            return new_indirect_block.return_code;
        }
        dest_node->block_indices[DIRECT_BLOCKS_PER_INODE - 1] = new_indirect_block.index;
        uint32_t *source_indirect_block = BLOCK_ADDRESS(indirect_block_index);
        uint32_t *dest_indirect_block = BLOCK_ADDRESS(new_indirect_block.index);
        for (size_t i = 0; i < NUMBER_OF_BLOCKS(source_node->entry_size) - DIRECT_BLOCKS_PER_INODE + 1; i++) {
            if (source_indirect_block[i] != -1) {
                block_id_result_t new_block = allocate_block();
                if (new_block.return_code != FS_OK) {
                    return new_block.return_code;
                }
                dest_indirect_block[i] = new_block.index;
                int8_t *source_block = (int8_t *)BLOCK_ADDRESS(source_indirect_block[i]);
                int8_t *dest_block = (int8_t *)BLOCK_ADDRESS(new_block.index);
                copy_data_from_buffer(source_block, dest_block, BLOCK_SIZE);
            }
        }
    }
    return FS_OK;
}


fs_result_t move_entry_operation(const uint32_t client_id, unsigned char *source_path, unsigned char *dest_dir, unsigned char *dest_name) {
    fs_result_t copy_result = copy_entry_operation(client_id, source_path, dest_dir, dest_name);
    if (copy_result != FS_OK) {
        return copy_result;
    }
    return delete_file_operation(client_id, source_path);
}


// ------------------------- MicroKit Interface -------------------------- //

void init(void) {
    microkit_dbg_puts("FILE SERVER: started\n");
    block_table = (uint8_t *)blocks_base;
    i_node_table = (i_node_t *)i_node_table_base;
    file_descriptor_table = (file_descriptor_t *)file_descriptor_table_base;
    client_buffers = (uint8_t *)lowest_client_buffer_base;

    // Initialize block table
    for (size_t i = 0; i < MAX_NUMBER_OF_BLOCKS; i++) {
        block_table[i] = 0;
    }
    // Initialize i-node table
    for (size_t i = 0; i < MAX_INODES; i++) {
        i_node_table[i].mode = 0;
    }
    // Initialize file descriptor table
    for (size_t i = 0; i < NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT; i++) {
        file_descriptor_table[i].i_node_index = -1;
    }

    // Create initial i-node block
    block_id_result_t initial_i_node_block = allocate_block();

    // Create root directory i-node
    i_node_t *root_i_node = &i_node_table[allocate_i_node().index];
    root_i_node->mode = 0b0001 | 0b0010 | PERM_PUBLIC << 2; // in use, dir, permissions
    root_i_node->owner_id = -1; // owned by file server
    root_i_node->block_indices[0] = initial_i_node_block.index;
    root_i_node->entry_size = 0;
}

void notified(microkit_channel client_id) {}

microkit_msginfo protected(microkit_channel channel, microkit_msginfo msginfo) {
    if (microkit_msginfo_get_count(msginfo) < 1) {
        microkit_mr_set(0, FS_ERR_INVALID_OP_CODE);
        return msginfo;
    }

    uint32_t operation = microkit_mr_get(0);
    int return_code = FS_ERR_UNSPECIFIED_ERROR;

    switch (operation) {
        case OP_CREATE_FILE: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t size = microkit_mr_get(1);
            uint8_t permissions = (uint8_t)microkit_mr_get(2);
            i_node_result_t i_node = create_entry((unsigned char *)(CLIENT_BUFFER_BASE(channel)), ROOT_DIRECTORY_I_NODE_INDEX, permissions, channel, CREATE_FILE);
            if (i_node.return_code != FS_OK) {
                return_code = i_node.return_code;
            } else {
                fs_result_t fd_result = open_file_operation(channel, permissions);
                return_code = fd_result;
            }
            break;
        }

        case OP_CREATE_DIRECTORY: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t size = microkit_mr_get(1);
            uint8_t permissions = (uint8_t)microkit_mr_get(2);
            i_node_result_t i_node = create_entry((unsigned char *)(CLIENT_BUFFER_BASE(channel)), ROOT_DIRECTORY_I_NODE_INDEX, permissions, channel, CREATE_DIRECTORY);
            return_code = i_node.return_code;
            break;
        }

        case OP_OPEN:
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint8_t requested_operations = (uint8_t)microkit_mr_get(1);
            return_code = open_file_operation(channel, requested_operations);
            break;


        case OP_CLOSE:
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = close_file_operation(channel, file_id);
            break;


        case OP_READ: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            size_t length = (size_t)microkit_mr_get(2);
            return_code = read_file_operation(channel, file_id, length);
            break;
        }

        case OP_WRITE: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            size_t write_length = (size_t)microkit_mr_get(2);
            return_code = write_file_operation(channel, file_id, write_length);
            break;
        }

        case OP_SEEK: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            uint32_t position = microkit_mr_get(2);
            return_code = seek_file_operation(channel, file_id, position);
            break;
        }

        case OP_DELETE: {
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = delete_file_operation(channel, file_id);
            break;
        }
            
        case OP_SET_PERMISSIONS: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            uint8_t new_permissions = (uint8_t)microkit_mr_get(2);
            return_code = set_file_permissions_operation(channel, file_id, new_permissions);
            break;
        }

        case OP_GET_PERMISSIONS: {
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = get_file_permissions_operation(channel, file_id);
            break;
        }

        case OP_GET_FILE_SIZE: {
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = get_entry_size_operation(channel, file_id);
            break;
        }

        case OP_EXISTS: {
            return_code = file_exists_operation(channel);
            break;
        }

        case OP_LIST: {
            return_code = list_files_operation(channel);
            break;
        }

        case OP_RENAME: {
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = rename_file_operation(channel, file_id);
            break;
        }

        case OP_COPY: {
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = copy_file_operation(channel, file_id);
            break;
        }

        case OP_MOVE: {
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = move_file_operation(channel, file_id);
            break;
        }

        default:
            return_code = FS_ERR_INVALID_OP_CODE;
            break;
    }

    microkit_mr_set(0, return_code);

    return msginfo;
}