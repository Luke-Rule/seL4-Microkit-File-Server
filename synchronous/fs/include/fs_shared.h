#pragma once
#include <stdint.h>
#include <stddef.h>

#define MAX_NAME_LENGTH 63
#define CLIENT_BUFFER_SIZE 0x40000

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

typedef struct {
    int rc;
    uint32_t file_id;
} fs_result_fileid_t;

typedef struct {
    int rc;
    uint8_t permissions;
} fs_result_permissions_t;

typedef struct {
    int rc;
    uint32_t size;
} fs_result_size_t;

typedef struct {
    int rc;
    uint8_t exists;
} fs_result_exists_t;

typedef struct {
    int rc;
    uint8_t *data_address;
    uint32_t bytes_read;
    uint32_t new_cursor_position;
} fs_result_read_t;

typedef struct {
    int rc;
    uint8_t *data_address;
} fs_result_list_t;

typedef struct {
    int rc;
    uint32_t bytes_written;
    uint32_t new_cursor_position;
} fs_result_write_t;