// File operations 
typedef enum {
    OP_CREATE = 0,
    OP_READ = 1,
    OP_WRITE = 2,
    OP_OPEN = 3, // not used yet
    OP_CLOSE = 4, // not used yet
    OP_DELETE = 5,
    OP_LIST = 6,
    OP_SET_PERMISSIONS = 7,
    OP_GET_PERMISSIONS = 8,
    OP_RENAME = 9,
    OP_GET_FILE_SIZE = 10,
    OP_EXISTS = 11,
    OP_COPY = 12
} file_operation_t;

// File operation permissions (higher value includes lower levels)
typedef enum {
    FILE_PERM_PRIVATE = 0,
    FILE_PERM_PUBLIC_EXISTS_AND_LIST = 1,
    FILE_PERM_PUBLIC_GET_FILE_SIZE = 2,
    FILE_PERM_PUBLIC_GET_PERMISSIONS = 3,
    FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE = 4,
    FILE_PERM_PUBLIC_WRITE_AND_DELETE_AND_RENAME = 5,
    FILE_PERM_PUBLIC_SET_PERMISSIONS = 6
} file_permission_t;

// Result codes (0 == success, other gives failure reason)
typedef enum {
    FS_OK = 0,
    FS_ERR_TABLE_FULL = 1,
    FS_ERR_FILE_EXCEEDS_MAX_SIZE = 2,
    FS_ERR_FILE_EXCEEDS_REMAINING_SPACE = 3,
    FS_ERR_INVALID_NAME = 4,
    FS_ERR_ALREADY_EXISTS = 5,
    FS_ERR_NOT_FOUND = 6,
    FS_ERR_PERMISSION = 7,
    FS_ERR_OUT_OF_BOUNDS = 8,
    FS_ERR_NAME_COLLISION = 9,
    FS_ERR_INVALID_OP_CODE = 10,
    FS_ERR_INCORRECT_OP_PARAM_COUNT = 11,
    FS_ERR_UNSPECIFIED_ERROR = 12
} fs_result_t;