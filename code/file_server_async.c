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
//TODO: do something about ending file names with 0
// ------------------------------ Definitions ----------------------------- //

// System parameters
#define NUMBER_OF_CLIENTS 1

// Client memory
#define MAX_QUEUE_ENTRIES 64
#define NUMBER_OF_BUFFERS_PER_CLIENT 64
#define CLIENT_TOTAL_BUFFER_SIZE 0x40000
#define CLIENT_INDIVIDUAL_BUFFER_SIZE 0x1000
#define CLIENT_QUEUE_SIZE 0x1000
#define BUFFER_TABLE_SIZE 0x1000
#define CLIENT_OFFSET (2 * (CLIENT_TOTAL_BUFFER_SIZE + CLIENT_QUEUE_SIZE) + BUFFER_TABLE_SIZE)
#define CLIENT_SUBMISSION_QUEUE_BASE(client_id) ((uintptr_t)clients + (uintptr_t)(client_id * CLIENT_OFFSET))
#define CLIENT_COMPLETION_QUEUE_BASE(client_id) ((uintptr_t)clients + (uintptr_t)(client_id * CLIENT_OFFSET + CLIENT_QUEUE_SIZE))
#define CLIENT_SUBMISSION_BUFFER_BASE(client_id) ((uintptr_t)clients + (uintptr_t)(client_id * CLIENT_OFFSET + 2 * CLIENT_QUEUE_SIZE))
#define CLIENT_COMPLETION_BUFFER_BASE(client_id) ((uintptr_t)clients + (uintptr_t)(client_id * CLIENT_OFFSET + 2 * CLIENT_QUEUE_SIZE + CLIENT_TOTAL_BUFFER_SIZE))
#define CLIENT_BUFFER_TABLE_BASE(client_id) ((uintptr_t)clients + (uintptr_t)(client_id * CLIENT_OFFSET + 2 * CLIENT_QUEUE_SIZE + 2 * CLIENT_TOTAL_BUFFER_SIZE))
#define CLIENT_SUBMISSION_BUFFER_TABLE_BASE(client_id) ((uint8_t *)(CLIENT_BUFFER_TABLE_BASE(client_id)))
#define CLIENT_COMPLETION_BUFFER_TABLE_BASE(client_id) ((uint8_t *)(CLIENT_BUFFER_TABLE_BASE(client_id) + (NUMBER_OF_BUFFERS_PER_CLIENT)))
#define CLIENT_READY_FLAG(client_id) (((uint32_t *)(CLIENT_SUBMISSION_QUEUE_BASE(client_id)) + 2))
#define CLIENT_COMPLETE_FLAG(client_id) (((uint32_t *)(CLIENT_COMPLETION_QUEUE_BASE(client_id)) + 2))
#define CLIENT_SUBMISSION_QUEUE_HEAD(client_id) (((uint32_t *)(CLIENT_SUBMISSION_QUEUE_BASE(client_id)) + 0))
#define CLIENT_SUBMISSION_QUEUE_TAIL(client_id) (((uint32_t *)(CLIENT_SUBMISSION_QUEUE_BASE(client_id)) + 1))
#define CLIENT_COMPLETION_QUEUE_HEAD(client_id) (((uint32_t *)(CLIENT_COMPLETION_QUEUE_BASE(client_id)) + 0))
#define CLIENT_COMPLETION_QUEUE_TAIL(client_id) (((uint32_t *)(CLIENT_COMPLETION_QUEUE_BASE(client_id)) + 1))
#define CLIENT_SUBMISSION_QUEUE_INDEX(client_id, index) (&((submission_queue_entry_t *)CLIENT_SUBMISSION_QUEUE_BASE(client_id))[index])
#define CLIENT_COMPLETION_QUEUE_INDEX(client_id, index) (&((completion_queue_entry_t *)CLIENT_COMPLETION_QUEUE_BASE(client_id))[index])
#define CLIENT_SUBMISSION_BUFFER(client_id, buffer_index) ((uint8_t *)(CLIENT_SUBMISSION_BUFFER_BASE(client_id) + (buffer_index * CLIENT_INDIVIDUAL_BUFFER_SIZE)))
#define CLIENT_COMPLETION_BUFFER(client_id, buffer_index) ((uint8_t *)(CLIENT_COMPLETION_BUFFER_BASE(client_id) + (buffer_index * CLIENT_INDIVIDUAL_BUFFER_SIZE)))

// File server
#define BLOCK_SIZE 0x1000
#define BLOCK_TABLE_SIZE 0x1F000
#define BLOCK_DATA_SIZE 0x1F018000
#define MAX_NUMBER_OF_BLOCKS (((int)(BLOCK_DATA_SIZE / BLOCK_SIZE)) > (BLOCK_TABLE_SIZE) ? (BLOCK_TABLE_SIZE) : ((int)(BLOCK_DATA_SIZE / BLOCK_SIZE)))
#define DIRECT_BLOCKS_PER_INODE 11
#define BLOCK_ADDRESS(block_index) (uint32_t *)((uintptr_t)blocks + (block_index * BLOCK_SIZE))
#define MAX_OPEN_FILES_PER_CLIENT 256
#define INODE_TABLE_SIZE 0x5B8000
#define MAX_INODES ((int)(INODE_TABLE_SIZE / sizeof(i_node_t)))
#define FILE_DESCRIPTOR_ENTRY_SIZE sizeof(struct file_descriptor)
#define FILE_DESCRIPTOR_OFFSET(client_id, file_index) ((uintptr_t)file_descriptor_table + client_id * MAX_OPEN_FILES_PER_CLIENT + file_index)
#define MAX_CHILD_ENTRIES_PER_BLOCK ((int)(BLOCK_SIZE / sizeof(child_entry_t)))
#define MAX_BLOCK_POINTERS_PER_INDIRECT_BLOCK ((int)(BLOCK_SIZE / sizeof(uint32_t)))
#define MAX_BLOCKS_PER_FILE (DIRECT_BLOCKS_PER_INODE + MAX_BLOCK_POINTERS_PER_INDIRECT_BLOCK)
#define NUMBER_OF_BLOCKS(entry_size) ((int)(entry_size / BLOCK_SIZE) + 1) // TODO: need to be exact?
#define MAX_CHILDREN_PER_DIRECTORY (MAX_BLOCKS_PER_FILE * MAX_CHILD_ENTRIES_PER_BLOCK)
#define GET_PARENT_I_NODE 1
#define GET_TARGET_I_NODE 0
#define READ 1
#define WRITE 0

// ------------------------------ Globals ------------------------------- //
//TODO maybe change to 16 bit
// TODO need to check all sizes of structures 

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
    uint32_t blocks_used;
    uint32_t block_indices[DIRECT_BLOCKS_PER_INODE + 1]; // last is indirect block
} typedef i_node_t;

struct i_node_result
{
    int32_t index;
    int return_code;
} typedef i_node_result_t;

struct child_entry
{
    unsigned char name[MAX_NAME_LENGTH];
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
uintptr_t i_node_table_base;
uintptr_t file_descriptor_table_base;
uintptr_t blocks_base;

uintptr_t lowest_client_queue_base;

int8_t *block_table;
file_descriptor_t *file_descriptor_table;
i_node_t *i_node_table;
int8_t *blocks;
int8_t *clients;

void copy_data_from_buffer(const uint8_t *src, uint8_t *dest, size_t length) {
    for (size_t i = 0; i < length; i++) {
        dest[i] = src[i];
    }
}

// maybe add a to
size_t  copy_string_from_buffer(const unsigned char *src, unsigned char *dest, size_t max_length) {
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


i_node_result_t allocate_i_node() {
    for (size_t i = 0; i < MAX_INODES; i++) {
        if ((i_node_table[i].mode & 0x1) == 0) {
            i_node_table[i].mode |= 0x1;
            return (i_node_result_t){i, FS_OK};
        }
    }
    microkit_dbg_puts("cant allocat i node\n");
    return (i_node_result_t){0, FS_ERR_INODE_TABLE_FULL};
}


void release_indirect_block(const uint32_t indirect_block_index, const int size_in_blocks) {
    uint32_t *indirect_block = BLOCK_ADDRESS(indirect_block_index);
    for (size_t i = 0; i < size_in_blocks; i++) {
        release_block(indirect_block[i]);
    }
}


void release_i_node(const uint32_t i_node_index) {
    if (i_node_index < MAX_INODES) {
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
    uint32_t *indirect_block = BLOCK_ADDRESS(parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]);
    for (int i = 0; i < parent_i_node->blocks_used; i++) {
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node->block_indices[i];
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
                if (get_parent) {
                    return (i_node_result_t){parent_i_node_index, FS_OK};
                }
                return (i_node_result_t){child_entries[j].i_node_index, FS_OK};
            } else if (cmp_result == PATH_SEGMENT_EQUAL) {
                while (*path != '/') {
                    path = &path[1];
                }
                if (i_node_table[child_entries[j].i_node_index].mode & 0b10) {
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

void increment_completion_queue_tail(const uint32_t client_id) {
    uint32_t *completion_queue_tail = CLIENT_COMPLETION_QUEUE_TAIL(client_id);
    if (*completion_queue_tail >= MAX_QUEUE_ENTRIES - 1) {
        // already checked theres space
        *completion_queue_tail = 1;
        return;
    }
    *completion_queue_tail = (*completion_queue_tail + 1);
}


void add_completion_entry(const uint32_t client_id, const uint8_t return_code, const uint32_t parameter1, const uint32_t parameter2, const uint32_t buffer_index) {
    uint32_t completion_tail_index = *CLIENT_COMPLETION_QUEUE_TAIL(client_id);
    microkit_dbg_puts("Adding completion entry at tail index: ");
    microkit_dbg_put32(completion_tail_index);
    microkit_dbg_puts("\n");
    completion_queue_entry_t *completion_queue_entry = CLIENT_COMPLETION_QUEUE_INDEX(client_id, completion_tail_index);
    completion_queue_entry->return_code = return_code;
    completion_queue_entry->parameter1 = parameter1;
    completion_queue_entry->parameter2 = parameter2;
    completion_queue_entry->buffer_index = buffer_index;
    increment_completion_queue_tail(client_id);
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
    child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
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

    // TODO: could do size of bytes
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


child_slot_and_block_result_t get_free_child_slot(const uint32_t parent_i_node_index) {
    i_node_t *parent_i_node = &i_node_table[parent_i_node_index];
    microkit_dbg_puts("checking parent ");
    microkit_dbg_put32(parent_i_node_index);
    microkit_dbg_puts("\n");
    uint32_t *indirect_block = BLOCK_ADDRESS(parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]);
    for (int i = 0; i < parent_i_node->blocks_used; i++) {
        microkit_dbg_puts("checking block ");
        microkit_dbg_put32(i);
        microkit_dbg_puts("\n");
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node->block_indices[i];
        } else {
            block_index = indirect_block[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
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
        uint32_t *indirect_block = BLOCK_ADDRESS(parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]);
        indirect_block[parent_i_node->blocks_used - DIRECT_BLOCKS_PER_INODE] = new_block.index;
    }
    parent_i_node->blocks_used += 1;
    return (child_slot_and_block_result_t){new_block.index, 0, FS_OK};
}


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
            if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operatons != requested_operations) {
                if (!valid_permissions(&i_node_table[i_node_index], client_id, requested_operations)) {
                    return (file_index_and_cursor_result_t){-1, -1, FS_ERR_PERMISSION};
                }
                file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operatons = requested_operations;
            }
            return (file_index_and_cursor_result_t){i, file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].cursor_position, FS_OK};
        }
    }
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index == -1) {
            if (!valid_permissions(&i_node_table[i_node_index], client_id, requested_operations)) {
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


block_search_result_t get_inode_block_index_from_file_index(const uint32_t file_index) {
    uint32_t block_index = file_index / BLOCK_SIZE;
    uint32_t block_offset = file_index % BLOCK_SIZE;
    if (block_index < DIRECT_BLOCKS_PER_INODE) {
        return (block_search_result_t){block_index, block_offset, 0};
    } else {
        return (block_search_result_t){DIRECT_BLOCKS_PER_INODE - block_index, block_offset, 1};
    }
}


fs_result_t copy_bytes_i_node(i_node_t *i_node, int8_t *client_buffer, size_t length, file_descriptor_t *fd, const int rnw) {
    size_t buffer_index = 0;
    block_search_result_t block_info = get_inode_block_index_from_file_index(fd->cursor_position);
    uint32_t *indirect_block = BLOCK_ADDRESS(i_node->block_indices[DIRECT_BLOCKS_PER_INODE]);
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
                    indirect_block = BLOCK_ADDRESS(i_node->block_indices[DIRECT_BLOCKS_PER_INODE]);
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
    return FS_OK;
}


void increment_submission_queue_head(const uint32_t client_id) {
    uint32_t *submission_queue_head = CLIENT_SUBMISSION_QUEUE_HEAD(client_id);
    if (*submission_queue_head >= MAX_QUEUE_ENTRIES - 1) {
        *submission_queue_head = 1;
        return;
    }
    *submission_queue_head = (*submission_queue_head + 1);
}


int get_free_completion_buffer(int client_id) {
    uint8_t *completion_buffer_table = CLIENT_COMPLETION_BUFFER_TABLE_BASE(client_id);
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        if (completion_buffer_table[i] == 0) {
            completion_buffer_table[i] = 1;
            return i;
        }
    }
    return -1;
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
    uint32_t *indirect_block = BLOCK_ADDRESS(parent_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]);
    for (int i = 0; i < parent_i_node->blocks_used; i++) {
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node->block_indices[i];
        } else {
            block_index = indirect_block[i - DIRECT_BLOCKS_PER_INODE];
        }
        child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
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
                if (i_node_table[child_entries[j].i_node_index].mode & 0b10) {
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


void open_file_operation(const uint32_t client_id, const uint8_t requested_operations, char *path) {
    i_node_result_t i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
    if (i_node_index.return_code < FS_OK) {
        microkit_dbg_puts("could not find i node\n");
        add_completion_entry(client_id, i_node_index.return_code, 0, 0, -1);
        return;
    }
    if (i_node_table[i_node_index.index].mode & 0b10) {
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


fs_result_t close_file_by_i_node_index(const uint32_t client_id, const uint32_t i_node_index) {
    microkit_dbg_puts("closing i node ");
    microkit_dbg_put32(i_node_index);
    microkit_dbg_puts("\n");
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        file_descriptor_t *fd = &file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i];
        if (fd->i_node_index == i_node_index) {
            fd->i_node_index = -1;
            fd->cursor_position = 0;
            fd->valid_operatons = 0;
            return FS_OK;
        }
    }
    return FS_ERR_FILE_DESCRIPTOR_NOT_FOUND;
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
    fd.descriptor->valid_operatons = 0;
    add_completion_entry(client_id, FS_OK, 0, 0, -1);
}


void read_file_operation(const uint32_t client_id, const uint32_t file_descriptor_index, const size_t length) {
    file_descriptor_result_t fd = get_file_descriptor(client_id, file_descriptor_index);
    if (fd.return_code != FS_OK) {
        add_completion_entry(client_id, fd.return_code, 0, 0, -1);
        return;
    }
    if (!(fd.descriptor->valid_operatons & PERM_READ)) {
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
    int8_t *client_buffer = (int8_t *)CLIENT_COMPLETION_BUFFER(client_id, buffer_index);
    int cursor_before = fd.descriptor->cursor_position;
    fs_result_t rc = copy_bytes_i_node(i_node, client_buffer, bytes_to_read, fd.descriptor, READ);
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
    if (!(fd.descriptor->valid_operatons & PERM_WRITE)) {
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, -1);
        return;
    }
    fs_result_t return_code = FS_OK;
    i_node_t *i_node = &i_node_table[fd.descriptor->i_node_index];
    //TODO this is grim
    if ((long long int)i_node->entry_size + (long long int)length - (long long int)fd.descriptor->cursor_position > (long long int)MAX_BLOCKS_PER_FILE * (long long int)BLOCK_SIZE) {
        return_code = FS_ERR_MAX_FILE_SIZE_REACHED;
        length = (long long int)MAX_BLOCKS_PER_FILE * (long long int)BLOCK_SIZE - (long long int)(i_node->entry_size + length - fd.descriptor->cursor_position);
    }
    microkit_dbg_puts("writing ");
    microkit_dbg_put32(length);
    microkit_dbg_puts(" bytes\n");
    int8_t *client_buffer = (int8_t *)CLIENT_SUBMISSION_BUFFER(client_id, buffer_index);
    int cursor_before = fd.descriptor->cursor_position;
    fs_result_t rc = copy_bytes_i_node(i_node, client_buffer, length, fd.descriptor, WRITE);
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


fs_result_t delete_directory_contents(const uint32_t i_node_index) {
    i_node_t *dir_i_node = &i_node_table[i_node_index];
    uint32_t *indirect_block = BLOCK_ADDRESS(dir_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]);
    for (int i = 0; i < dir_i_node->blocks_used; i++) {
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = dir_i_node->block_indices[i];
        } else {
            block_index = indirect_block[i - DIRECT_BLOCKS_PER_INODE];
        }
        microkit_dbg_puts("deleting block ");
        microkit_dbg_put32(block_index);
        microkit_dbg_puts("\n");
        child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].name[0] == '\0') {
                continue;
            }
            if (i_node_table[child_entries[j].i_node_index].mode & 0b10) {
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
    // TODO: could reuse other func here if mod
    i_node_t *parent_i_node_ptr = &i_node_table[parent_i_node.index];
    uint32_t *indirect_block = BLOCK_ADDRESS(parent_i_node_ptr->block_indices[DIRECT_BLOCKS_PER_INODE]);
    for (int i = 0; i < parent_i_node_ptr->blocks_used; i++) {
        uint32_t block_index;
        if (i < DIRECT_BLOCKS_PER_INODE) {
            block_index = parent_i_node_ptr->block_indices[i];
        } else {
            block_index = indirect_block[i - DIRECT_BLOCKS_PER_INODE];
        }
        //TODO: could move items to fill gap rather than just nulling, or remove if at end
        child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
        for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
            if (child_entries[j].i_node_index == i_node_index.index) {
                child_entries[j].name[0] = '\0';
                parent_i_node_ptr->entry_size -= 1;
                break;
            }
        }
    }
    if (i_node_table[i_node_index.index].mode & 0b10) {
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
    if (!(dir_i_node->mode & 0b10)) {
        add_completion_entry(client_id, FS_ERR_INVALID_PATH, 0, 0, -1);
        return;
    }
    if (!valid_permissions(dir_i_node, client_id, PERM_READ)) {
        add_completion_entry(client_id, FS_ERR_PERMISSION, 0, 0, -1);
        return;
    }
    const int buffer_index = get_free_completion_buffer(client_id);
    uint32_t *indirect_block = BLOCK_ADDRESS(dir_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]);
    int chars_written = 0;
    for (int i = 0; i < dir_i_node->blocks_used; i++) {
        if (chars_written >= CLIENT_TOTAL_BUFFER_SIZE) {
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
                chars_written += copy_string_from_buffer(child_entries[j].name, &((unsigned char *)CLIENT_COMPLETION_BUFFER(client_id, buffer_index))[chars_written], (MAX_NAME_LENGTH > CLIENT_TOTAL_BUFFER_SIZE - chars_written) ? CLIENT_TOTAL_BUFFER_SIZE - chars_written : MAX_NAME_LENGTH);
                if (chars_written >= CLIENT_TOTAL_BUFFER_SIZE) {
                    ((unsigned char *)CLIENT_COMPLETION_BUFFER(client_id, buffer_index))[chars_written - 1] = '\n';
                    break;
                }
                ((unsigned char *)CLIENT_COMPLETION_BUFFER(client_id, buffer_index))[chars_written] = '\n';
                chars_written += 1;
            }

        }
    }
    //TODO: elsewhere?
    ((unsigned char *)CLIENT_COMPLETION_BUFFER(client_id, buffer_index))[chars_written] = '\0';
    add_completion_entry(client_id, FS_OK, 0, 0, buffer_index);
}

// //TODO change to get name from parent directory
// fs_result_t rename_entry_operation(const uint32_t client_id, unsigned char *path, unsigned char *new_name) {
//     unsigned char *path = (unsigned char *)CLIENT_BUFFER_BASE(client_id);
//     if (!valid_name(new_name)) {
//         return FS_ERR_INVALID_PATH;
//     }
//     if (compare_names(path, new_name) == FULL_PATH_EQUAL) {
//         return FS_OK;
//     }
//     i_node_result_t parent_i_node_index = get_i_node_index(path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_PARENT_I_NODE);
//     if (parent_i_node_index.return_code != FS_OK) {
//         return parent_i_node_index.return_code;
//     }
//     i_node_t *dir_i_node = &i_node_table[parent_i_node_index.index];
//     if (!(dir_i_node->mode & 0b10)) {
//         return FS_ERR_INVALID_PATH;
//     }
//     if (!valid_permissions(*dir_i_node, client_id, PERM_WRITE)) {
//         return FS_ERR_PERMISSION;
//     }
//     uint32_t *indirect_block = BLOCK_ADDRESS(dir_i_node->block_indices[DIRECT_BLOCKS_PER_INODE]);
//     for (int i = 0; i < NUMBER_OF_BLOCKS(dir_i_node->entry_size); i++) {
//         uint32_t block_index;
//         if (i < DIRECT_BLOCKS_PER_INODE) {
//             block_index = dir_i_node->block_indices[i];
//         } else {
//             block_index = indirect_block[i - DIRECT_BLOCKS_PER_INODE];
//         }
//         child_entry_t *child_entries = (child_entry_t *)BLOCK_ADDRESS(block_index);
//         for (size_t j = 0; j < MAX_CHILD_ENTRIES_PER_BLOCK; j++) {
//             if (child_entries[j].name[0] == '\0') {
//                 continue;
//             }
//             // path here needs to be only the name of the entry, need func
//             if (compare_names(path, child_entries[j].name)) {
//                 copy_string_from_buffer(new_name, child_entries[j].name, MAX_NAME_LENGTH);
//                 return FS_OK;
//             }
//         }
//     }
//     return FS_ERR_UNSPECIFIED_ERROR;
// }

// //TODO change to get name from parent directory
// fs_result_t copy_entry_operation(const uint32_t client_id, unsigned char *source_path, unsigned char *dest_dir, unsigned char *dest_name) {
//     if (compare_names(source_path, dest_dir) == FULL_PATH_EQUAL) {
//         return FS_ERR_INVALID_PATH;
//     }
//     i_node_result_t source_i_node_index = get_i_node_index(source_path, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_TARGET_I_NODE);
//     if (source_i_node_index.return_code != FS_OK) {
//         return source_i_node_index.return_code;
//     }
//     if (!valid_permissions(i_node_table[source_i_node_index.index], client_id, PERM_READ)) {
//         return FS_ERR_PERMISSION;
//     }
//     i_node_result_t dest_parent_i_node_index = get_i_node_index(dest_dir, ROOT_DIRECTORY_I_NODE_INDEX, client_id, GET_PARENT_I_NODE);
//     if (dest_parent_i_node_index.return_code != FS_OK) {
//         return dest_parent_i_node_index.return_code;
//     }
//     if (!valid_permissions(i_node_table[dest_parent_i_node_index.index], client_id, PERM_WRITE)) {
//         return FS_ERR_PERMISSION;
//     }
//     if (!(i_node_table[source_i_node_index.index].mode & 0b10)) {
//         return FS_ERR_INVALID_PATH;
//     }
//     child_slot_and_block_result_t slot_info = get_free_child_slot(dest_parent_i_node_index.index);
//     if (slot_info.return_code != FS_OK) {
//         return slot_info.return_code;
//     }
//     i_node_result_t new_i_node = add_entry(dest_parent_i_node_index.index, dest_name, (i_node_table[source_i_node_index.index].mode >> 2) & 0b111, client_id, slot_info.block_index, slot_info.entry_index, ((i_node_table[source_i_node_index.index].mode & 0b10) >> 1) & 0b1);
//     if (new_i_node.return_code != FS_OK) {
//         return new_i_node.return_code;
//     }
//     i_node_t *source_node = &i_node_table[source_i_node_index.index];
//     i_node_t *dest_node = &i_node_table[new_i_node.index];
//     dest_node->entry_size = source_node->entry_size;
//     for (size_t i = 0; i < DIRECT_BLOCKS_PER_INODE; i++) {
//         if (source_node->block_indices[i] != -1) {
//             block_id_result_t new_block = allocate_block();
//             if (new_block.return_code != FS_OK) {
//                 return new_block.return_code;
//             }
//             dest_node->block_indices[i] = new_block.index;
//             int8_t *source_block = (int8_t *)BLOCK_ADDRESS(source_node->block_indices[i]);
//             int8_t *dest_block = (int8_t *)BLOCK_ADDRESS(new_block.index);
//             copy_data_from_buffer(source_block, dest_block, BLOCK_SIZE);
//         }
//     }
//     const uint32_t indirect_block_index = source_node->block_indices[DIRECT_BLOCKS_PER_INODE];
//     if (indirect_block_index != -1) {
//         block_id_result_t new_indirect_block = allocate_block();
//         if (new_indirect_block.return_code != FS_OK) {
//             return new_indirect_block.return_code;
//         }
//         dest_node->block_indices[DIRECT_BLOCKS_PER_INODE] = new_indirect_block.index;
//         uint32_t *source_indirect_block = BLOCK_ADDRESS(indirect_block_index);
//         uint32_t *dest_indirect_block = BLOCK_ADDRESS(new_indirect_block.index);
//         for (size_t i = 0; i < NUMBER_OF_BLOCKS(source_node->entry_size) - DIRECT_BLOCKS_PER_INODE; i++) {
//             if (source_indirect_block[i] != -1) {
//                 block_id_result_t new_block = allocate_block();
//                 if (new_block.return_code != FS_OK) {
//                     return new_block.return_code;
//                 }
//                 dest_indirect_block[i] = new_block.index;
//                 int8_t *source_block = (int8_t *)BLOCK_ADDRESS(source_indirect_block[i]);
//                 int8_t *dest_block = (int8_t *)BLOCK_ADDRESS(new_block.index);
//                 copy_data_from_buffer(source_block, dest_block, BLOCK_SIZE);
//             }
//         }
//     }
//     return FS_OK;
// }

// //TODO change to get name from parent directory
// fs_result_t move_entry_operation(const uint32_t client_id, unsigned char *source_path, unsigned char *dest_dir, unsigned char *dest_name) {
//     fs_result_t copy_result = copy_entry_operation(client_id, source_path, dest_dir, dest_name);
//     if (copy_result != FS_OK) {
//         return copy_result;
//     }
//     return delete_entry_operation(client_id, source_path);
// }


// ------------------------- MicroKit Interface -------------------------- //

void init(void) {
    microkit_dbg_puts("FILE SERVER: started\n");
    block_table = (uint8_t *)block_table_base;
    i_node_table = (i_node_t *)i_node_table_base;
    file_descriptor_table = (file_descriptor_t *)file_descriptor_table_base;
    blocks = (uint8_t *)blocks_base;
    clients = (uint8_t *)lowest_client_queue_base;

    microkit_dbg_puts("FILE SERVER: initialising block table\n");
    for (size_t i = 0; i < MAX_NUMBER_OF_BLOCKS; i++) {
        block_table[i] = 0;
    }
    microkit_dbg_puts("FILE SERVER: initialising inode table\n");
    for (size_t i = 0; i < MAX_INODES; i++) {
        i_node_table[i].mode = 0;
    }
    microkit_dbg_puts("FILE SERVER: initialising fd table\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT; i++) {
        file_descriptor_table[i].i_node_index = -1;
    }
    microkit_dbg_puts("FILE SERVER: initialising client queues\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        uint32_t *submission_queue_head = CLIENT_SUBMISSION_QUEUE_HEAD(i);
        uint32_t *submission_queue_tail = CLIENT_SUBMISSION_QUEUE_TAIL(i);
        uint32_t *completion_queue_tail = CLIENT_COMPLETION_QUEUE_TAIL(i);
        uint32_t *completion_queue_head = CLIENT_COMPLETION_QUEUE_HEAD(i);
        *submission_queue_head = 1;
        *submission_queue_tail = 1;
        *completion_queue_head = 1;
        *completion_queue_tail = 1;
    }

    // set all buffers to 0
    microkit_dbg_puts("FILE SERVER: initialising buffer table\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        uint8_t *submission_buffer_table = CLIENT_SUBMISSION_BUFFER_TABLE_BASE(i);
        uint8_t *completion_buffer_table = CLIENT_COMPLETION_BUFFER_TABLE_BASE(i);
        for (size_t j = 0; j < NUMBER_OF_BUFFERS_PER_CLIENT; j++) {
            submission_buffer_table[j] = 0;
            completion_buffer_table[j] = 0;
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
    //print sub tail
    microkit_dbg_puts("sub tail is: ");
    microkit_dbg_put32(*CLIENT_SUBMISSION_QUEUE_TAIL(0));
    microkit_dbg_putc('\n');
}


void set_free_submission_buffer(int client_id, int buffer_index) {
    if (buffer_index < 0 || buffer_index >= NUMBER_OF_BUFFERS_PER_CLIENT) {
        return;
    }
    uint8_t *submission_buffer_table = CLIENT_SUBMISSION_BUFFER_TABLE_BASE(client_id);
    submission_buffer_table[buffer_index] = 0;
}


// TODO prob return value whether entry existed, then can loop over this for certain amount of ops or all entries? Or loop within here.
void service_client(uint32_t client_id) {
    while (1) {
        microkit_dbg_puts("FILE SERVER: servicing client: ");
        microkit_dbg_put32(client_id);
        microkit_dbg_putc('\n');
        uint32_t submission_head = *CLIENT_SUBMISSION_QUEUE_HEAD(client_id);
        uint32_t submission_tail = *CLIENT_SUBMISSION_QUEUE_TAIL(client_id);
        if (submission_head == submission_tail) {
            microkit_dbg_puts("FILE SERVER: no submission entries\n");
            break;
        }
        uint32_t completion_head = *CLIENT_COMPLETION_QUEUE_HEAD(client_id);
        uint32_t completion_tail = *CLIENT_COMPLETION_QUEUE_TAIL(client_id);
        if (completion_tail + 1 == completion_head || (completion_head == 1 && completion_tail == MAX_QUEUE_ENTRIES)) {
            microkit_dbg_puts("FILE SERVER: no free completion entries\n");
            break;
        }
        // TODO: depending on op, check completion buffer space too
        submission_queue_entry_t *submission_entry = CLIENT_SUBMISSION_QUEUE_INDEX(client_id, submission_head);
        uint32_t operation = submission_entry->operation_code;

        switch (operation) {
            case OP_CREATE_FILE: {
                microkit_dbg_puts("FILE SERVER: CREATE FILE OPERATION\n");
                uint8_t permissions = (uint8_t)submission_entry->parameter1;
                microkit_dbg_puts("creating with path: ");
                microkit_dbg_puts((char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)));
                microkit_dbg_putc('\n');
                i_node_result_t i_node = create_entry((unsigned char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)), ROOT_DIRECTORY_I_NODE_INDEX, permissions, client_id, CREATE_FILE);
                if (i_node.return_code == FS_OK) {
                    microkit_dbg_puts("opening created file\n");
                    open_file_operation(client_id, permissions, (char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)));
                }
                set_free_submission_buffer(client_id, submission_entry->buffer_index); //TODO could put this somewhere better
                break;
            }

            case OP_CREATE_DIRECTORY: {
                microkit_dbg_puts("FILE SERVER: CREATE DIRECTORY OPERATION\n");
                uint8_t permissions = (uint8_t)submission_entry->parameter1;
                microkit_dbg_puts("creating with path: ");
                microkit_dbg_puts((char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)));
                microkit_dbg_putc('\n');
                i_node_result_t i_node = create_entry((unsigned char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)), ROOT_DIRECTORY_I_NODE_INDEX, permissions, client_id, CREATE_DIRECTORY);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_OPEN:
                uint8_t requested_operations = (uint8_t)submission_entry->parameter1;
                open_file_operation(client_id, requested_operations, (char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)));
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
                delete_entry_operation(client_id, (unsigned char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)));
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }
                
            case OP_SET_PERMISSIONS: {
                microkit_dbg_puts("FILE SERVER: SET PERMISSIONS OPERATION\n");
                uint8_t new_permissions = (uint8_t)submission_entry->parameter1;
                set_entry_permissions_operation(client_id, new_permissions, (unsigned char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)));
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_GET_PERMISSIONS: {
                microkit_dbg_puts("FILE SERVER: GET PERMISSIONS OPERATION\n");
                get_entry_permissions_operation(client_id, (unsigned char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)));
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_GET_SIZE: {
                microkit_dbg_puts("FILE SERVER: GET SIZE OPERATION\n");
                get_entry_size_operation(client_id, (unsigned char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)));
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_EXISTS: {
                microkit_dbg_puts("FILE SERVER: EXISTS OPERATION\n");
                entry_exists_operation(client_id, (unsigned char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)));
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_LIST: {
                microkit_dbg_puts("FILE SERVER: LIST OPERATION\n");
                list_directory_operation(client_id, (unsigned char *)(CLIENT_SUBMISSION_BUFFER(client_id, submission_entry->buffer_index)));
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            // TODO: need to add a function to get the separate paths from client buffer
            // case OP_RENAME: {
            //     if (microkit_msginfo_get_count(msginfo) < 1) {
            //         return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
            //         break;
            //     }
            //     return_code = rename_entry_operation(channel);
            //     break;
            // }

            // case OP_COPY: {
            //     if (microkit_msginfo_get_count(msginfo) < 1) {
            //         return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
            //         break;
            //     }
            //     return_code = copy_entry_operation(channel);
            //     break;
            // }

            // case OP_MOVE: {
            //     if (microkit_msginfo_get_count(msginfo) < 1) {
            //         return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
            //         break;
            //     }
            //     return_code = move_entry_operation(channel);
            //     break;
            // }

            default:
                microkit_dbg_puts("FILE SERVER: INVALID OPERATION CODE\n");
                break;
        }

        increment_submission_queue_head(client_id);
    }
    //TODO: if we arent looping
    *CLIENT_READY_FLAG(client_id) = 0;
    *CLIENT_COMPLETE_FLAG(client_id) = 1;
}


void poll_clients() {
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        if (*CLIENT_READY_FLAG(i)) {
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