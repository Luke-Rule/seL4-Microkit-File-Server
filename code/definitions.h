#pragma once
#define MAX_NAME_LENGTH 64 // TODO: update functions to handle null terminator reducing this by 1
#define CLIENT_BUFFER_SIZE 0x1000

// ANSI color codes for terminal output (used by tests)
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

#define FULL_PATH_EQUAL 0
#define FULL_PATH_NOT_EQUAL -1
#define PATH_SEGMENT_EQUAL 1

#define CREATE_DIRECTORY 1
#define CREATE_FILE 0
#define ROOT_DIRECTORY_I_NODE_INDEX 0

// File operations 
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
    OP_RENAME = 10,
    OP_GET_SIZE = 11,
    OP_EXISTS = 12,
    OP_COPY = 13,
    OP_BLOCK_READ = 14,
    OP_BLOCK_WRITE = 15,
    OP_SEEK = 16,
    OP_MOVE = 17
} file_operation_t;

// File operation permissions (higher value includes lower levels)
// typedef enum {
//     FILE_PERM_PRIVATE = 0,
//     FILE_PERM_PUBLIC_EXISTS_AND_LIST = 1,
//     FILE_PERM_PUBLIC_GET_FILE_SIZE = 2,
//     FILE_PERM_PUBLIC_GET_PERMISSIONS = 3,
//     FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE = 4,
//     FILE_PERM_PUBLIC = 5
// } file_permission_t;


typedef enum {
    PERM_PRIVATE = 0b000,
    PERM_READ = 0b001,
    PERM_WRITE = 0b010,
    PERM_EXECUTE = 0b100,
    PERM_PUBLIC = 0b111
} permissions_t;

struct submission_queue_entry
{
    uint8_t operation_code;
    uint32_t parameter1;
    uint32_t parameter2;
    uint32_t buffer_index;
} typedef submission_queue_entry_t;

struct completion_queue_entry
{
    uint8_t return_code;
    uint32_t parameter1;
    uint32_t parameter2;
    uint32_t buffer_index;
} typedef completion_queue_entry_t;

struct file_server_interface {
    submission_queue_entry_t *file_server_submission_queue;
    completion_queue_entry_t *file_server_completion_queue;
    uint8_t *file_server_submission_buffer;
    uint8_t *file_server_completion_buffer;
    uint8_t *buffer_table;
} typedef file_server_interface_t;

typedef enum {
    READ_OP = 0b01,
    WRITE_OP = 0b10,
    READ_WRITE_OP = 0b11
} file_open_operations_t;

// Result codes (0 == success, other gives failure reason)
//TODO: add more error codes 
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