#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define CLIENT_BUFFER_SIZE 0x1000u
#define CLIENT_DATA_PAGE_SIZE 0x81000u

#define MAX_NAME_LENGTH 63
#define MAX_QUEUE_ENTRIES 64
#define NUMBER_OF_BUFFERS_PER_CLIENT 64

typedef enum {
    OP_CREATE_FILE = 0,
    OP_CREATE_DIRECTORY = 1,
    OP_READ = 2,
    OP_WRITE = 3,
    OP_OPEN = 4, 
    OP_CLOSE = 5,
    OP_DELETE = 6,
    OP_LIST = 7,
    OP_SET_PERMISSIONS = 8,
    OP_GET_PERMISSIONS = 9,
    OP_GET_SIZE = 10,
    OP_EXISTS = 11,
    OP_BLOCK_READ = 12,
    OP_BLOCK_WRITE = 13,
    OP_SEEK = 14,
} file_operation_t;

struct client_flags {
    bool ready_flag;
    bool complete_flag;
    bool finished_running_flag;
    uint8_t padding;
} typedef client_flags_t;

struct buffer {
    uint8_t data[CLIENT_BUFFER_SIZE];
} typedef buffer_t;

struct submission_queue_entry
{
    file_operation_t operation_code;
    uint32_t parameter1;
    uint32_t parameter2;
    size_t buffer_index;
} typedef submission_queue_entry_t;

struct completion_queue_entry
{
    uint8_t return_code;
    uint32_t parameter1;
    uint32_t parameter2;
    size_t buffer_index;
} typedef completion_queue_entry_t;

#define CLIENT_DATA_INTERNAL_ALIGNMENT_PADDING ((sizeof(size_t) - (sizeof(client_flags_t) % sizeof(size_t))) % sizeof(size_t))
#define CLIENT_DATA_PADDING_AMOUNT (CLIENT_DATA_PAGE_SIZE - (sizeof(client_flags_t) + sizeof(size_t) * 4 + sizeof(submission_queue_entry_t) * MAX_QUEUE_ENTRIES + sizeof(completion_queue_entry_t) * MAX_QUEUE_ENTRIES + sizeof(uint8_t) * NUMBER_OF_BUFFERS_PER_CLIENT * 2 + sizeof(buffer_t) * NUMBER_OF_BUFFERS_PER_CLIENT * 2 + CLIENT_DATA_INTERNAL_ALIGNMENT_PADDING))

struct client {
    size_t submission_queue_head;
    size_t submission_queue_tail;
    size_t completion_queue_head;
    size_t completion_queue_tail;
    client_flags_t flags;
    submission_queue_entry_t submission_queue[MAX_QUEUE_ENTRIES];
    completion_queue_entry_t completion_queue[MAX_QUEUE_ENTRIES];
    bool submission_buffer_table[NUMBER_OF_BUFFERS_PER_CLIENT];
    bool completion_buffer_table[NUMBER_OF_BUFFERS_PER_CLIENT];
    buffer_t submission_buffers[NUMBER_OF_BUFFERS_PER_CLIENT];
    buffer_t completion_buffers[NUMBER_OF_BUFFERS_PER_CLIENT];
    uint8_t padding[CLIENT_DATA_PADDING_AMOUNT];
} typedef client_t;

_Static_assert(sizeof(client_t) == CLIENT_DATA_PAGE_SIZE, "client_t must exactly match CLIENT_DATA_PAGE_SIZE");

typedef enum {
    PERM_PRIVATE = 0b000,
    PERM_READ = 0b001,
    PERM_WRITE = 0b010,
    PERM_EXECUTE = 0b100,
    PERM_PUBLIC = 0b111
} permissions_t;

typedef enum {
    READ_OP = 0b01,
    WRITE_OP = 0b10,
    READ_WRITE_OP = 0b11
} file_open_operations_t;

// Result codes (0 == success, other gives failure reason)
typedef enum {
    FS_OK = 0,
    FS_ERR_INODE_TABLE_FULL = 1,
    FS_ERR_FILE_DESCRIPTOR_NOT_FOUND = 2,
    FS_ERR_NO_BLOCKS_REMAINING = 3,
    FS_ERR_INVALID_PATH = 4,
    FS_ERR_ALREADY_EXISTS = 5,
    FS_ERR_NOT_FOUND = 6,
    FS_ERR_PERMISSION = 7,
    FS_ERR_OUT_OF_BOUNDS = 8,
    FS_ERR_INVALID_OP_CODE = 9,
    FS_ERR_INCORRECT_OP_PARAM_COUNT = 10,
    FS_ERR_UNSPECIFIED_ERROR = 11,
    FS_ERR_BUFFER_TOO_SMALL = 12,
    FS_ERR_MAX_OPEN_FILES_REACHED = 13,
    FS_ERR_MAX_FILE_SIZE_REACHED = 14,
    FS_ERR_MAX_DIR_SIZE_REACHED = 15,
    FS_ERROR_NO_FREE_SUBMISSION_QUEUE_SLOTS = 16,
    FS_ERROR_NO_FREE_COMPLETION_QUEUE_SLOTS = 17,
    FS_ERROR_NO_FREE_SUBMISSION_BUFFERS = 18,
    FS_ERROR_NO_FREE_COMPLETION_BUFFERS = 19,
    FS_ERROR_NO_COMPLETION_ENTRIES_AVAILABLE = 20
} fs_result_t;