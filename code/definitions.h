#pragma once
#define MAX_FILE_NAME_LENGTH 64 // TODO: update functions to handle null terminator reducing this by 1
#define CLIENT_BUFFER_SIZE 0x40000

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
    OP_GET_FILE_SIZE = 11,
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

// Result codes (0 == success, other gives failure reason)
typedef enum {
    FS_OK = 0,
    FS_ERR_INODE_TABLE_FULL = -1,
    FS_ERR_FILE_DESCRIPTOR_NOT_FOUND = -2,
    FS_ERR_NO_BLOCKS_REMAINING = -3,
    FS_ERR_INVALID_PATH = -4,
    FS_ERR_ALREADY_EXISTS = -5,
    FS_ERR_NOT_FOUND = -6,
    FS_ERR_PERMISSION = -7,
    FS_ERR_OUT_OF_BOUNDS = -8,
    FS_ERR_INVALID_OP_CODE = -9,
    FS_ERR_INCORRECT_OP_PARAM_COUNT = -10,
    FS_ERR_UNSPECIFIED_ERROR = -11,
    FS_ERR_BUFFER_TOO_SMALL = -12,
    FS_ERR_MAX_OPEN_FILES_REACHED = -13,
    FS_ERR_MAX_FILE_SIZE_REACHED = -14,
    FS_ERR_MAX_DIR_SIZE_REACHED = -15
} fs_result_t;