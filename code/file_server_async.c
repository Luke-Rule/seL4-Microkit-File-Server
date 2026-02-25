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
#define BLOCK_SIZE 0x1000
#define MAX_NUMBER_OF_BLOCKS 0x10000
#define MAX_NUMBER_OF_INODES 0x10000
#define DIRECT_BLOCKS_PER_INODE 11
#define MAX_OPEN_FILES_PER_CLIENT 256

// Maximums to check against
#define MAX_CHILD_ENTRIES_PER_BLOCK ((int)(BLOCK_SIZE / sizeof(child_entry_t)))
#define MAX_BLOCK_POINTERS_PER_INDIRECT_BLOCK ((int)(BLOCK_SIZE / sizeof(uint32_t)))
#define MAX_BLOCKS_PER_FILE (DIRECT_BLOCKS_PER_INODE + MAX_BLOCK_POINTERS_PER_INDIRECT_BLOCK)

// Function parameters
#define GET_PARENT_I_NODE 1
#define GET_TARGET_I_NODE 0
#define READ 1
#define WRITE 0
#define IS_FILE_BIT_SET 0b00
#define IS_DIRECTORY_BIT_SET 0b10

// ------------------------------ Structs ------------------------------- //

struct block {
    uint8_t data[BLOCK_SIZE];
} typedef block_t;

struct file_descriptor
{
    uint32_t i_node_index;
    uint32_t cursor_position;
    uint8_t valid_operations;
    uint8_t padding[3];
} typedef file_descriptor_t;

struct i_node
{
    uint32_t entry_size;
    uint32_t blocks_used;
    uint32_t block_indices[DIRECT_BLOCKS_PER_INODE + 1]; // last is indirect block
    uint8_t mode; // 3 for perm, 1 for dir, 1 for in use 
    uint8_t owner_id;
    uint8_t padding[2];
} typedef i_node_t;

struct child_entry
{
    unsigned char name[MAX_NAME_LENGTH];
    uint32_t i_node_index;
} typedef child_entry_t;

// ----------------- Result function return structs --------------------- //

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

struct i_node_result
{
    int32_t index;
    int return_code;
} typedef i_node_result_t;

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


// ------------------------------ Globals ------------------------------- //

uintptr_t fs_memory_base;
uintptr_t clients_memory_base;

uint8_t *block_table;
file_descriptor_t *file_descriptor_table;
i_node_t *i_node_table;
block_t *blocks;
client_t *clients;

// ------------------------------ Utility Functions ------------------------------- //

int32_t compare_names(const unsigned char *name1, const unsigned char *name2) {
    for (size_t i = 0; i < MAX_NAME_LENGTH; i++) {
        if (name1[i] == '/') {
            microkit_dbg_puts("part\n");
            return PATH_SEGMENT_EQUAL;
        }
        if (name1[i] == '\0') {
            microkit_dbg_puts("full\n");
            return FULL_PATH_EQUAL;
        }
        if (name1[i] != name2[i]) {
            microkit_dbg_puts("not\n");
            return FULL_PATH_NOT_EQUAL;
        }
    }
    microkit_dbg_puts("eq2\n");
    return 0; 
}


int valid_name(const unsigned char *name) {
    microkit_dbg_puts("validating name: ");
    microkit_dbg_puts((const char *)name);
    microkit_dbg_puts("\n");
    if (name[0] == '\0' || name[0] == '/') {
        return 0;
    }
    for (size_t i = 0; i < MAX_NAME_LENGTH; i++) {
        if (name[i] == '\0') {
            return 1;
        }
        if (name[i] == '/') {
            return 0;
        }
    }
    return 0;
}


int valid_permissions(const i_node_t *i_node, const uint8_t client_id, const permissions_t required) {
    if (i_node->owner_id == client_id) {
        return 1;
    }
    permissions_t dir_perm = (i_node->mode >> 2) & 0b111;
    microkit_dbg_puts("checking permissions: ");
    microkit_dbg_put32(dir_perm);
    microkit_dbg_puts(" against required: ");
    microkit_dbg_put32(required);
    microkit_dbg_puts("\n");
    if ((dir_perm & required) == required) {
        return 1;
    }
    return 0;
}

// ------------------------------ Buffer copy functions ------------------------------- //

void copy_data_from_buffer(const uint8_t *src, uint8_t *dest, size_t length) {
    for (size_t i = 0; i < length; i++) {
        dest[i] = src[i];
    }
}


size_t copy_string_from_buffer(const unsigned char *src, unsigned char *dest, size_t max_length) {
    size_t i;
    for (i = 0; i < max_length - 1; i++) {
        dest[i] = src[i];
        if (dest[i] == '\0') {
            return i;
        }
    }
    // truncate if it exceeds max_length
    dest[max_length - 1] = '\0';
    return max_length - 1;
}

// ------------------------------ Block management functions ------------------------------- //

block_id_result_t allocate_block() {
    for (size_t i = 0; i < MAX_NUMBER_OF_BLOCKS; i++) {
        if (block_table[i] == 0) {
            block_table[i] = 1;
            return (block_id_result_t){i, FS_OK};
        }
    }
    return (block_id_result_t){0, FS_ERR_NO_BLOCKS_REMAINING};
}


void release_block(const uint32_t block_index) {
    if (block_index < MAX_NUMBER_OF_BLOCKS && block_table[block_index] == 1) {
        block_table[block_index] = 0;
    }
}


void release_indirect_block(const uint32_t indirect_block_index, const int size_in_blocks) {
    uint32_t *indirect_entries = (uint32_t *)&blocks[indirect_block_index].data;
    for (size_t i = 0; i < size_in_blocks; i++) {
        release_block(indirect_entries[i]);
    }
}

// ------------------------------ I Node management functions ------------------------------- //

i_node_result_t allocate_i_node() {
    for (size_t i = 0; i < MAX_NUMBER_OF_INODES; i++) {
        if ((i_node_table[i].mode & 0x1) == 0) {
            i_node_table[i].mode |= 0x1;
            return (i_node_result_t){i, FS_OK};
        }
    }

    microkit_dbg_puts("cant allocat i node\n");
    return (i_node_result_t){0, FS_ERR_INODE_TABLE_FULL};
}


void release_i_node(const uint32_t i_node_index) {
    if (i_node_index < MAX_NUMBER_OF_INODES) {
        i_node_table[i_node_index].mode = 0;
        for (size_t i = 0; i < i_node_table[i_node_index].blocks_used; i++) {
            uint32_t block_index;
            if (i >= DIRECT_BLOCKS_PER_INODE) {
                release_indirect_block(i_node_table[i_node_index].block_indices[DIRECT_BLOCKS_PER_INODE], i_node_table[i_node_index].blocks_used - DIRECT_BLOCKS_PER_INODE);
                return;
            }
            
            block_index = i_node_table[i_node_index].block_indices[i];
            release_block(block_index);
        }
    }
}


i_node_result_t get_i_node_index(unsigned char *path, const uint32_t parent_i_node_index, const uint8_t client_id, const int get_parent) {
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

// ------------------------------ Client queue management functions ------------------------------- //

void increment_completion_queue_tail(const uint32_t client_id) {
    if (clients[client_id].completion_queue_tail >= MAX_QUEUE_ENTRIES - 1) {
        // already checked theres space
        clients[client_id].completion_queue_tail = 0;
        return;
    }
    clients[client_id].completion_queue_tail = clients[client_id].completion_queue_tail + 1;
}


void add_completion_entry(const uint32_t client_id, const uint8_t return_code, const uint32_t parameter1, const uint32_t parameter2, const uint32_t buffer_index) {
    microkit_dbg_puts("Adding completion entry at tail index: ");
    microkit_dbg_put32(clients[client_id].completion_queue_tail);
    microkit_dbg_puts("\n");
    completion_queue_entry_t *completion_queue_entry = &clients[client_id].completion_queue[clients[client_id].completion_queue_tail];
    completion_queue_entry->return_code = return_code;
    completion_queue_entry->parameter1 = parameter1;
    completion_queue_entry->parameter2 = parameter2;
    completion_queue_entry->buffer_index = buffer_index;
    increment_completion_queue_tail(client_id);
}


void increment_submission_queue_head(const uint32_t client_id) {
    if (clients[client_id].submission_queue_head >= MAX_QUEUE_ENTRIES - 1) {
        clients[client_id].submission_queue_head = 0;
        return;
    }
    clients[client_id].submission_queue_head = clients[client_id].submission_queue_head + 1;
}

// ------------------------------ Client buffer management functions ------------------------------- //

int is_free_completion_buffer(int client_id) {
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        if (clients[client_id].completion_buffer_table[i] == 0) {
            return 1;
        }
    }
    return 0;
}


int get_free_completion_buffer(int client_id) {
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        if (clients[client_id].completion_buffer_table[i] == 0) {
            clients[client_id].completion_buffer_table[i] = 1;
            return i;
        }
    }
    return -1;
}

// ------------------------------ File descriptor table management functions ------------------------------- //

file_descriptor_result_t get_file_descriptor(const uint32_t client_id, const uint32_t file_index) {
    if (file_index >= MAX_OPEN_FILES_PER_CLIENT) {
        return (file_descriptor_result_t){NULL, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND};
    }
    file_descriptor_t *fd = &file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + file_index];
    if (fd->i_node_index == -1) {
        return (file_descriptor_result_t){NULL, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND};
    }
    return (file_descriptor_result_t){fd, FS_OK};
}

file_index_and_cursor_result_t add_i_node_to_fd_table(const uint32_t client_id, const uint32_t i_node_index, const uint8_t requested_operations) {
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index == i_node_index) {
            if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operations != requested_operations) {
                if (!valid_permissions(&i_node_table[i_node_index], client_id, requested_operations)) {
                    return (file_index_and_cursor_result_t){-1, -1, FS_ERR_PERMISSION};
                }
                file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operations = requested_operations;
            }
            return (file_index_and_cursor_result_t){i, file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].cursor_position, FS_OK};
        }
    }
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index == -1) {
            if (!valid_permissions(&i_node_table[i_node_index], client_id, requested_operations)) {
                return (file_index_and_cursor_result_t){-1, -1, FS_ERR_PERMISSION};
            }
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operations = requested_operations;
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index = i_node_index;
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].cursor_position = 0;
            return (file_index_and_cursor_result_t){i, 0, FS_OK};
        }
    }
    return (file_index_and_cursor_result_t){-1, -1, FS_ERR_MAX_OPEN_FILES_REACHED};
}


fs_result_t close_file_by_i_node_index(const uint32_t client_id, const uint32_t i_node_index) {
    microkit_dbg_puts("closing i node ");
    microkit_dbg_put32(i_node_index);
    microkit_dbg_puts("\n");
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        file_descriptor_t *fd = &file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i];
        if (fd->i_node_index == i_node_index) {
            fd->i_node_index = -1;
            fd->cursor_position = 0;
            fd->valid_operations = 0;
            return FS_OK;
        }
    }
    return FS_ERR_FILE_DESCRIPTOR_NOT_FOUND;
}

// ------------------------------ File data functions ------------------------------- //

block_search_result_t get_inode_block_index_from_file_index(const uint32_t file_index) {
    uint32_t block_index = file_index / BLOCK_SIZE;
    uint32_t block_offset = file_index % BLOCK_SIZE;
    if (block_index < DIRECT_BLOCKS_PER_INODE) {
        return (block_search_result_t){block_index, block_offset, 0};
    } else {
        return (block_search_result_t){DIRECT_BLOCKS_PER_INODE - block_index, block_offset, 1};
    }
}


fs_result_t copy_bytes_i_node(i_node_t *i_node, uint8_t *client_buffer, size_t length, file_descriptor_t *fd, const int rnw) {
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
        uint8_t *block_data = &blocks[block_index].data[0];
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

// ------------------------------ Directory entry management functions ------------------------------- //

child_slot_and_block_result_t get_free_child_slot(const uint32_t parent_i_node_index) {
    i_node_t *parent_i_node = &i_node_table[parent_i_node_index];
    microkit_dbg_puts("checking parent ");
    microkit_dbg_put32(parent_i_node_index);
    microkit_dbg_puts("\n");
    uint32_t *indirect_block_data = (uint32_t *)&blocks[parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (int i = 0; i < parent_i_node->blocks_used; i++) {
        microkit_dbg_puts("checking block ");
        microkit_dbg_put32(i);
        microkit_dbg_puts("\n");
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node->block_indices[i];
        } else {
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)&blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            microkit_dbg_puts("checking slot ");
            microkit_dbg_put32(j);
            microkit_dbg_puts("\n");
            if (child_entries[j].name[0] == '\0') {
                return (child_slot_and_block_result_t){block_index, j, FS_OK};
            }
        }
    }
    microkit_dbg_puts("need new block\n");
    block_id_result_t new_block = allocate_block();
    if (new_block.return_code != FS_OK) {
        return (child_slot_and_block_result_t){0, 0, new_block.return_code};
    }
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


i_node_result_t add_entry(const uint32_t parent_i_node_index, unsigned char *name, const permissions_t permissions, const uint8_t client_id, const uint32_t block_index, const uint32_t entry_index, const int is_directory) {
    microkit_dbg_puts(name);
    microkit_dbg_puts("\n");
    if (!valid_name(name)) {
        add_completion_entry(client_id, FS_ERR_INVALID_PATH, 0, 0, -1);
        return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
    }
    i_node_result_t new_i_node_info = allocate_i_node();
    if (new_i_node_info.return_code != FS_OK) {
        add_completion_entry(client_id, new_i_node_info.return_code, 0, 0, -1);
        return new_i_node_info;
    }
    i_node_t *parent_i_node = &i_node_table[parent_i_node_index];
    child_entry_t *child_entries = (child_entry_t *)&blocks[block_index].data;
    copy_string_from_buffer(name, child_entries[entry_index].name, MAX_NAME_LENGTH);
    microkit_dbg_puts("parent ");
    microkit_dbg_put32(parent_i_node_index);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("block ");
    microkit_dbg_put32(block_index);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("entry ");
    microkit_dbg_put32(entry_index);
    microkit_dbg_puts("\n");
    child_entries[entry_index].i_node_index = new_i_node_info.index;

    block_id_result_t new_block = allocate_block();
    if (new_block.return_code != FS_OK) {
        release_i_node(new_i_node_info.index);
        add_completion_entry(client_id, new_block.return_code, 0, 0, -1);
        return (i_node_result_t){-1, new_block.return_code};
    }

    parent_i_node->entry_size += 1;

    i_node_table[new_i_node_info.index].mode = 0b00001 | (is_directory << 1) | (permissions << 2); // in use, dir, permissions
    i_node_table[new_i_node_info.index].owner_id = client_id;
    i_node_table[new_i_node_info.index].block_indices[0] = new_block.index;
    i_node_table[new_i_node_info.index].entry_size = 0;
    i_node_table[new_i_node_info.index].blocks_used = 1;

    if (is_directory) {
        add_completion_entry(client_id, FS_OK, 0, 0, -1);
    }
    return new_i_node_info;
}


i_node_result_t create_entry(unsigned char *path, const uint32_t parent_i_node_index, const permissions_t permissions, const uint8_t client_id, const int is_directory) {
    microkit_dbg_puts("entering dir ");
    microkit_dbg_puts(path);
    microkit_dbg_puts("\n");
    if (path[0] != '/') {
        add_completion_entry(client_id, FS_ERR_INVALID_PATH, 0, 0, -1);
        return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
    }
    path = &path[1];
    microkit_dbg_puts("entering dir ");
    microkit_dbg_puts(path);
    microkit_dbg_puts("\n");
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
            microkit_dbg_puts("comparing to ");
            microkit_dbg_puts(child_entries[j].name);
            microkit_dbg_puts("\n");
            int32_t cmp_result = compare_names(path, child_entries[j].name);
            if (cmp_result == FULL_PATH_EQUAL) {
                add_completion_entry(client_id, FS_ERR_ALREADY_EXISTS, 0, 0, -1);
                return (i_node_result_t){-1, FS_ERR_ALREADY_EXISTS};
            } else if (cmp_result == PATH_SEGMENT_EQUAL) {
                while (*path != '/') {
                    path = &path[1];
                }
                if (i_node_table[child_entries[j].i_node_index].mode & IS_DIRECTORY_BIT_SET) {
                    if (!valid_permissions(&i_node_table[child_entries[j].i_node_index], client_id, PERM_EXECUTE)) {
                        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, -1);
                        return (i_node_result_t){-1, FS_ERR_PERMISSION};
                    }
                    return create_entry(path, child_entries[j].i_node_index, permissions, client_id, is_directory);
                } else {
                    add_completion_entry(client_id, FS_ERR_INVALID_PATH, 0, 0, -1);
                    return (i_node_result_t){-1, FS_ERR_INVALID_PATH};
                }
            }
        }
    }
    child_slot_and_block_result_t slot_info = get_free_child_slot(parent_i_node_index);
    microkit_dbg_puts("child to root: ");
    microkit_dbg_put32(slot_info.entry_index);
    microkit_dbg_putc('\n');
    if (slot_info.return_code != FS_OK) {
        add_completion_entry(client_id, slot_info.return_code, 0, 0, -1);
        return (i_node_result_t){-1, slot_info.return_code};
    }
    return add_entry(parent_i_node_index, path, permissions, client_id, slot_info.block_index, slot_info.entry_index, is_directory);
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
        microkit_dbg_puts("deleting block ");
        microkit_dbg_put32(block_index);
        microkit_dbg_puts("\n");
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
            release_i_node(child_entries[j].i_node_index);
            child_entries[j].name[0] = '\0';
        }
    }
    dir_i_node->entry_size = 0;
    dir_i_node->blocks_used = 0;
    return FS_OK;
}

void defragment_directory(i_node_t *parent_i_node) {
    microkit_dbg_puts("defragmenting directory i node ");
    microkit_dbg_put32(parent_i_node - i_node_table);
    microkit_dbg_puts("\n");
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


void delete_entry_operation(const uint32_t client_id, unsigned char *path) {
    i_node_result_t parent_i_node = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_PARENT_I_NODE);
    if (parent_i_node.return_code != FS_OK) {
        add_completion_entry(client_id, parent_i_node.return_code, 0, 0, -1);
        return;
    }
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, -1);
        return;
    }
    if (i_node_table[i_node_index.index].owner_id != client_id && !valid_permissions(&i_node_table[i_node_index.index], client_id, PERM_WRITE)) {
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, -1);
        return;
    }

    i_node_t *parent_i_node_ptr = &i_node_table[parent_i_node.index];
    uint32_t *indirect_block_data = (uint32_t *)&blocks[parent_i_node_ptr->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    for (int i = 0; i < parent_i_node_ptr->blocks_used; i++) {
        uint32_t block_index;
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
    microkit_dbg_puts("checking if can free block\n");
    microkit_dbg_puts("entry size: ");
    microkit_dbg_put32((int)(parent_i_node_ptr->entry_size / MAX_CHILD_ENTRIES_PER_BLOCK) + 1);
    microkit_dbg_puts("\nblocks used: ");
    microkit_dbg_put32(parent_i_node_ptr->blocks_used);
    microkit_dbg_puts("\n");
    if ((int)(parent_i_node_ptr->entry_size / MAX_CHILD_ENTRIES_PER_BLOCK) + 1 < parent_i_node_ptr->blocks_used) {
        defragment_directory(parent_i_node_ptr);
        int block_to_free_index = parent_i_node_ptr->blocks_used - 1;
        uint32_t block_index;
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
    if (i_node_table[i_node_index.index].mode & IS_DIRECTORY_BIT_SET) {
        fs_result_t res = delete_directory_contents(i_node_index.index);
        release_i_node(i_node_index.index);
        add_completion_entry(client_id, res, 0, 0, -1);
    } else {
        microkit_dbg_puts("releasing i node\n");
        release_i_node(i_node_index.index);
        microkit_dbg_puts("closing file\n");
        fs_result_t res = close_file_by_i_node_index(client_id, i_node_index.index);
        add_completion_entry(client_id, res, 0, 0, -1);
    }
}


void set_entry_permissions_operation(const uint32_t client_id, const permissions_t permissions, unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, -1);
        return;
    }
    if (i_node_table[i_node_index.index].owner_id != client_id) {
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, -1);
        return;
    }
    i_node_table[i_node_index.index].mode = (i_node_table[i_node_index.index].mode & 0b00011) | (permissions << 2);
    add_completion_entry(client_id, FS_OK, 0, 0, -1);
}


void get_entry_permissions_operation(const uint32_t client_id, unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, -1);
        return;
    }
    uint8_t permissions = (i_node_table[i_node_index.index].mode >> 2) & 0b111;
    add_completion_entry(client_id, FS_OK, permissions, 0, -1);
}


void get_entry_size_operation(const uint32_t client_id, unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, -1);
        return;
    }
    add_completion_entry(client_id, FS_OK, i_node_table[i_node_index.index].entry_size, 0, -1);
}


void entry_exists_operation(const uint32_t client_id, unsigned char *path) {
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, FS_OK, 0, 0, -1);
        return;
    }
    add_completion_entry(client_id, FS_OK, 1, 0, -1);
}


void list_directory_operation(const uint32_t client_id, unsigned char *path) {
    microkit_dbg_puts("listing dir ");
    microkit_dbg_puts(path);
    microkit_dbg_puts("\n");
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code != FS_OK) {
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, -1);
        return;
    }
    i_node_t *dir_i_node = &i_node_table[i_node_index.index];
    if (!(dir_i_node->mode & IS_DIRECTORY_BIT_SET)) {
        add_completion_entry(client_id, FS_ERR_INVALID_PATH, 0, 0, -1);
        return;
    }
    if (!valid_permissions(dir_i_node, client_id, PERM_READ)) {
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, -1);
        return;
    }
    const int buffer_index = get_free_completion_buffer(client_id);
    uint8_t *client_buffer_data = &clients[client_id].completion_buffers[buffer_index].data[0];
    uint32_t *indirect_block_data = (uint32_t *)&blocks[dir_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]].data;
    int chars_written = 0;
    for (int i = 0; i < dir_i_node->blocks_used; i++) {
        if (chars_written >= CLIENT_BUFFER_SIZE) {
            break;
        }
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = dir_i_node->block_indices[i];
        } else {
            block_index = indirect_block_data[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)&blocks[block_index].data;
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] != '\0') {
                // TODO: bro
                chars_written += copy_string_from_buffer(child_entries[j].name, &client_buffer_data[chars_written], (MAX_NAME_LENGTH > CLIENT_BUFFER_SIZE - chars_written) ? CLIENT_BUFFER_SIZE - chars_written : MAX_NAME_LENGTH);
                if (chars_written >= CLIENT_BUFFER_SIZE) {
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

void open_file_operation(const uint32_t client_id, const uint8_t requested_operations, char *path) {
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code < FS_OK) {
        microkit_dbg_puts("could not find i node\n");
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, -1);
        return;
    }
    if (i_node_table[i_node_index.index].mode & IS_DIRECTORY_BIT_SET) {
        microkit_dbg_puts("tried to open directory as file\n");
        add_completion_entry(client_id, FS_ERR_INVALID_PATH, 0, 0, -1);
        return;
    }
    file_index_and_cursor_result_t fd = add_i_node_to_fd_table(client_id, i_node_index.index, requested_operations);
    if (fd.return_code != FS_OK) {
        microkit_dbg_puts("could not add to fd table\n");
        add_completion_entry(client_id, fd.return_code, 0, 0, -1);
        return;
    }
    add_completion_entry(client_id, FS_OK, fd.file_index, fd.cursor_position, -1);
}


void close_file_operation(const uint32_t client_id, const uint32_t file_descriptor_index) {
    microkit_dbg_puts("closing fd ");
    microkit_dbg_put32(file_descriptor_index);
    microkit_dbg_puts("\n");
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client_id, fd.return_code, 0, 0, -1);
        return;
    }
    fd.descriptor->i_node_index = -1;
    fd.descriptor->cursor_position = 0;
    fd.descriptor->valid_operations = 0;
    add_completion_entry(client_id, FS_OK, 0, 0, -1);
}


void read_file_operation(const uint32_t client_id, const uint32_t file_descriptor_index, const size_t length) {
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client_id, fd.return_code, 0, 0, -1);
        return;
    }
    if (!(fd.descriptor->valid_operations & PERM_READ)) {
        microkit_dbg_puts("no read perm\n");
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, -1);
        return;
    }
    fs_result_t return_code = FS_OK;
    i_node_t *i_node = &i_node_table[fd.descriptor->i_node_index];
    size_t bytes_to_read = length;
    if (fd.descriptor->cursor_position + length > i_node->entry_size) {
        bytes_to_read = i_node->entry_size - fd.descriptor->cursor_position;
        return_code = FS_ERR_OUT_OF_BOUNDS;
    }
    const int buffer_index = get_free_completion_buffer(client_id);
    uint8_t *client_buffer_data = &clients[client_id].completion_buffers[buffer_index].data[0];
    int cursor_before = fd.descriptor->cursor_position;
    fs_result_t rc = copy_bytes_i_node(i_node, client_buffer_data, bytes_to_read, fd.descriptor, READ);
    if (rc != FS_OK) {
        add_completion_entry(client_id, rc, 0, 0, buffer_index);
        return;
    }
    add_completion_entry(client_id, return_code, fd.descriptor->cursor_position - cursor_before, fd.descriptor->cursor_position, buffer_index);
}


void write_file_operation(const uint32_t client_id, const uint32_t file_descriptor_index, size_t length, const size_t buffer_index) {
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client_id, fd.return_code, 0, 0, -1);
        return;
    }
    if (!(fd.descriptor->valid_operations & PERM_WRITE)) {
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, -1);
        return;
    }
    fs_result_t return_code = FS_OK;
    i_node_t *i_node = &i_node_table[fd.descriptor->i_node_index];
    if (length + fd.descriptor->cursor_position >= MAX_BLOCKS_PER_FILE * BLOCK_SIZE) {
        return_code = FS_ERR_MAX_FILE_SIZE_REACHED;
        length = MAX_BLOCKS_PER_FILE * BLOCK_SIZE - (fd.descriptor->cursor_position) - 1;
    }
    microkit_dbg_puts("writing ");
    microkit_dbg_put32(length);
    microkit_dbg_puts(" bytes\n");
    uint8_t *client_buffer_data = &clients[client_id].submission_buffers[buffer_index].data[0];
    int cursor_before = fd.descriptor->cursor_position;
    fs_result_t rc = copy_bytes_i_node(i_node, client_buffer_data, length, fd.descriptor, WRITE);
    microkit_dbg_puts("write complete\n");
    if (rc != FS_OK) {
        add_completion_entry(client_id, rc, 0, 0, -1);
        return;
    }
    add_completion_entry(client_id, return_code, fd.descriptor->cursor_position - cursor_before, fd.descriptor->cursor_position, -1);
}


void seek_file_operation(const uint32_t client_id, const uint32_t file_descriptor_index, const uint32_t position) {
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client_id, fd.return_code, 0, 0, -1);
        return;
    }
    if (position > i_node_table[fd.descriptor->i_node_index].entry_size) {
        add_completion_entry(client_id, FS_ERR_OUT_OF_BOUNDS, 0, 0, -1);
        return;
    }
    fd.descriptor->cursor_position = position;
    add_completion_entry(client_id, FS_OK, 0, 0, -1);
}

// ------------------------- MicroKit Interface -------------------------- //

void init(void) {
    microkit_dbg_puts("FILE SERVER: started\n");
    block_table = (uint8_t *)fs_memory_base;
    i_node_table = (i_node_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS);
    file_descriptor_table = (file_descriptor_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS + sizeof(i_node_t) * MAX_NUMBER_OF_INODES);
    blocks = (block_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS + sizeof(i_node_t) * MAX_NUMBER_OF_INODES + sizeof(file_descriptor_t) * NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT);
    clients = (client_t *)clients_memory_base;

    microkit_dbg_puts("FILE SERVER: initialising block table\n");
    for (size_t i = 0; i < MAX_NUMBER_OF_BLOCKS; i++) {
        block_table[i] = 0;
    }
    microkit_dbg_puts("FILE SERVER: initialising inode table\n");
    for (size_t i = 0; i < MAX_NUMBER_OF_INODES; i++) {
        i_node_table[i].mode = 0;
    }
    microkit_dbg_puts("FILE SERVER: initialising fd table\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT; i++) {
        file_descriptor_table[i].i_node_index = -1;
    }
    microkit_dbg_puts("FILE SERVER: initialising client queues\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        clients[i].submission_queue_head = 0;
        clients[i].submission_queue_tail = 0;
        clients[i].completion_queue_head = 0;
        clients[i].completion_queue_tail = 0;
    }

    microkit_dbg_puts("FILE SERVER: initialising buffer table\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        for (size_t j = 0; j < NUMBER_OF_BUFFERS_PER_CLIENT; j++) {
            clients[i].submission_buffer_table[j] = 0;
            clients[i].completion_buffer_table[j] = 0;
        }
    }

    microkit_dbg_puts("FILE SERVER: allocating root block\n");
    block_id_result_t initial_i_node_block = allocate_block();

    microkit_dbg_puts("FILE SERVER: initialising root block\n");
    i_node_t *root_i_node = &i_node_table[allocate_i_node().index];
    root_i_node->mode = 0b00001 | 0b00010 | (PERM_EXECUTE || PERM_READ) << 2; // in use, dir, permissions
    root_i_node->owner_id = -1; // owned by file server
    root_i_node->block_indices[0] = initial_i_node_block.index;
    root_i_node->entry_size = 0;
    root_i_node->blocks_used = 1;
}


void set_free_submission_buffer(int client_id, int buffer_index) {
    if (buffer_index < 0 || buffer_index >= NUMBER_OF_BUFFERS_PER_CLIENT) {
        return;
    }
    clients[client_id].submission_buffer_table[buffer_index] = 0;
}


void service_client(uint32_t client_id) {
    client_t *client = &clients[client_id];
    // TODO: limit number of operations per service to prevent starvation of other clients
    while (1) {
        microkit_dbg_puts("FILE SERVER: servicing client: ");
        microkit_dbg_put32(client_id);
        microkit_dbg_putc('\n');
        uint32_t submission_head = clients[client_id].submission_queue_head;
        uint32_t submission_tail = clients[client_id].submission_queue_tail;
        if (submission_head == submission_tail) {
            microkit_dbg_puts("FILE SERVER: no submission entries\n");
            break;
        }
        if (client->completion_queue_tail + 1 == client->completion_queue_head || (client->completion_queue_head == 1 && client->completion_queue_tail == MAX_QUEUE_ENTRIES - 1)) {
            microkit_dbg_puts("FILE SERVER: no free completion entries\n");
            break;
        }
        submission_queue_entry_t *submission_entry = &client->submission_queue[submission_head];
        uint32_t operation = submission_entry->operation_code;

        if ((operation == OP_READ || operation == OP_LIST) && !is_free_completion_buffer(client_id)) {
            microkit_dbg_puts("FILE SERVER: no free completion buffer for operation\n");
            break;
        }

        switch (operation) {
            case OP_CREATE_FILE: {
                microkit_dbg_puts("FILE SERVER: CREATE FILE OPERATION\n");
                uint8_t permissions = (uint8_t)submission_entry->parameter1;
                unsigned char *path = &client->submission_buffers[submission_entry->buffer_index].data[0];
                microkit_dbg_puts("creating with path: ");
                microkit_dbg_puts((char *)path);
                microkit_dbg_putc('\n');
                i_node_result_t i_node = create_entry(path, ROOT_DIRECTORY_I_NODE_INDEX, permissions, client_id, CREATE_FILE);
                if (i_node.return_code == FS_OK) {
                    microkit_dbg_puts("opening created file\n");
                    open_file_operation(client_id, permissions, path);
                }
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_CREATE_DIRECTORY: {
                microkit_dbg_puts("FILE SERVER: CREATE DIRECTORY OPERATION\n");
                uint8_t permissions = (uint8_t)submission_entry->parameter1;
                unsigned char *path = &client->submission_buffers[submission_entry->buffer_index].data[0];
                microkit_dbg_puts("creating with path: ");
                microkit_dbg_puts((char *)path);
                microkit_dbg_putc('\n');
                i_node_result_t i_node = create_entry(path, ROOT_DIRECTORY_I_NODE_INDEX, permissions, client_id, CREATE_DIRECTORY);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_OPEN:
                uint8_t requested_operations = (uint8_t)submission_entry->parameter1;
                open_file_operation(client_id, requested_operations, (char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;


            case OP_CLOSE:
                microkit_dbg_puts("FILE SERVER: CLOSE OPERATION\n");
                uint32_t file_id = (uint32_t)submission_entry->parameter1;
                close_file_operation(client_id, file_id);
                break;


            case OP_READ: {
                microkit_dbg_puts("FILE SERVER: READ OPERATION\n");
                uint32_t file_id = (uint32_t)submission_entry->parameter1;
                size_t length = (size_t)submission_entry->parameter2;
                read_file_operation(client_id, file_id, length);
                break;
            }

            case OP_WRITE: {
                microkit_dbg_puts("FILE SERVER: WRITE OPERATION\n");
                uint32_t file_id = (uint32_t)submission_entry->parameter1;
                size_t write_length = (size_t)submission_entry->parameter2;
                write_file_operation(client_id, file_id, write_length, submission_entry->buffer_index);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_SEEK: {
                microkit_dbg_puts("FILE SERVER: SEEK OPERATION\n");
                uint32_t file_id = (uint32_t)submission_entry->parameter1;
                uint32_t position = (uint32_t)submission_entry->parameter2;
                seek_file_operation(client_id, file_id, position);
                break;
            }

            case OP_DELETE: {
                microkit_dbg_puts("FILE SERVER: DELETE OPERATION\n");
                delete_entry_operation(client_id, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }
                
            case OP_SET_PERMISSIONS: {
                microkit_dbg_puts("FILE SERVER: SET PERMISSIONS OPERATION\n");
                uint8_t new_permissions = (uint8_t)submission_entry->parameter1;
                set_entry_permissions_operation(client_id, new_permissions, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_GET_PERMISSIONS: {
                microkit_dbg_puts("FILE SERVER: GET PERMISSIONS OPERATION\n");
                get_entry_permissions_operation(client_id, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_GET_SIZE: {
                microkit_dbg_puts("FILE SERVER: GET SIZE OPERATION\n");
                get_entry_size_operation(client_id, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_EXISTS: {
                microkit_dbg_puts("FILE SERVER: EXISTS OPERATION\n");
                entry_exists_operation(client_id, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_LIST: {
                microkit_dbg_puts("FILE SERVER: LIST OPERATION\n");
                list_directory_operation(client_id, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            default:
                microkit_dbg_puts("FILE SERVER: INVALID OPERATION CODE\n");
                break;
        }

        increment_submission_queue_head(client_id);
    }

    clients[client_id].flags.ready_flag = 0;
    clients[client_id].flags.complete_flag = 1;
}


void poll_clients() {
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        if (clients[i].flags.ready_flag && !clients[i].flags.complete_flag) {
            microkit_dbg_puts("FILE SERVER: client ");
            microkit_dbg_put32(i);
            microkit_dbg_puts(" had lost notif, servicing now.\n");
            service_client(i);
        }
    }
}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo) {
    service_client(ch);
    poll_clients();
}

void notified(microkit_channel ch) {
    service_client(ch);
    poll_clients();
}