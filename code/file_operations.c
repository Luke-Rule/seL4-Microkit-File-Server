#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "definitions.h"

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


void debug_print_return_code(const char *operation, int return_code) {
    microkit_dbg_puts("CLIENT: ");
    microkit_dbg_puts(operation);
    microkit_dbg_puts(" operation returned code: ");
    switch (return_code)
    {
        case FS_OK:
            microkit_dbg_puts("FS_OK: Operation completed successfully.\n");
            break;
        case FS_ERR_INODE_TABLE_FULL:
            microkit_dbg_puts("FS_ERR_INODE_TABLE_FULL: No more inodes available.\n");
            break;
        case FS_ERR_FILE_DESCRIPTOR_NOT_FOUND:
            microkit_dbg_puts("FS_ERR_FILE_DESCRIPTOR_NOT_FOUND: File descriptor not found.\n");
            break;
        case FS_ERR_NO_BLOCKS_REMAINING:
            microkit_dbg_puts("FS_ERR_NO_BLOCKS_REMAINING: No more blocks available.\n");
            break;
        case FS_ERR_INVALID_PATH:
            microkit_dbg_puts("FS_ERR_INVALID_PATH: The specified path is invalid.\n");
            break;
        case FS_ERR_ALREADY_EXISTS:
            microkit_dbg_puts("FS_ERR_ALREADY_EXISTS: The file or directory already exists.\n");
            break;
        case FS_ERR_NOT_FOUND:
            microkit_dbg_puts("FS_ERR_NOT_FOUND: The specified file or directory was not found.\n");
            break;
        case FS_ERR_PERMISSION:
            microkit_dbg_puts("FS_ERR_PERMISSION: Permission denied for the requested operation.\n");
            break;
        case FS_ERR_OUT_OF_BOUNDS:
            microkit_dbg_puts("FS_ERR_OUT_OF_BOUNDS: Operation attempted out-of-bounds access.\n");
            break;
        case FS_ERR_INVALID_OP_CODE:
            microkit_dbg_puts("FS_ERR_INVALID_OP_CODE: The operation code is invalid.\n");
            break;
        case FS_ERR_INCORRECT_OP_PARAM_COUNT:
            microkit_dbg_puts("FS_ERR_INCORRECT_OP_PARAM_COUNT: Incorrect number of parameters for the operation.\n");
            break;
        case FS_ERR_UNSPECIFIED_ERROR:
            microkit_dbg_puts("FS_ERR_UNSPECIFIED_ERROR: An unspecified error occurred.\n");
            break;
        case FS_ERR_BUFFER_TOO_SMALL:
            microkit_dbg_puts("FS_ERR_BUFFER_TOO_SMALL: The provided buffer is too small.\n");
            break;
        case FS_ERR_MAX_OPEN_FILES_REACHED:
            microkit_dbg_puts("FS_ERR_MAX_OPEN_FILES_REACHED: Maximum number of open files reached.\n");
            break;
        case FS_ERR_MAX_FILE_SIZE_REACHED:
            microkit_dbg_puts("FS_ERR_MAX_FILE_SIZE_REACHED: Maximum file size reached.\n");
            break;
        case FS_ERR_MAX_DIR_SIZE_REACHED:
            microkit_dbg_puts("FS_ERR_MAX_DIR_SIZE_REACHED: Maximum directory size reached.\n");
            break;
        default:
            microkit_dbg_puts("Unknown error code.\n");
            break;
    }
}


fs_result_fileid_t send_create_file_request(const unsigned char *file_name, const permissions_t permissions, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    copy_string_from_buffer(file_name, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);

    microkit_mr_set(0, OP_CREATE_FILE);
    microkit_mr_set(1, permissions);

    microkit_dbg_puts("CLIENT: requested to create file: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with permissions: ");
    microkit_dbg_put32((uint32_t)permissions);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    fs_result_fileid_t res;
    res.rc = microkit_mr_get(0);
    debug_print_return_code("create", res.rc);
    res.file_id = *((uint32_t *)fs_buffer_base);
    return res;
}


int send_create_directory_request(const unsigned char *dir_name, const permissions_t permissions, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    copy_string_from_buffer(dir_name, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);

    microkit_mr_set(0, OP_CREATE_DIRECTORY);
    microkit_mr_set(1, permissions);

    microkit_dbg_puts("CLIENT: requested to create directory: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with permissions: ");
    microkit_dbg_put32((uint32_t)permissions);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("create directory", return_code);

    return return_code;
}


fs_result_fileid_t send_open_file_request(const file_open_operations_t ops, const unsigned char *file_name, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    copy_string_from_buffer(file_name, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);

    microkit_mr_set(0, OP_OPEN);
    microkit_mr_set(1, ops);

    microkit_dbg_puts("CLIENT: requested to open file: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    
    fs_result_fileid_t res;
    res.rc = microkit_mr_get(0);
    debug_print_return_code("open", res.rc);
    res.file_id = *((uint32_t *)fs_buffer_base);
    return res;
}


int send_close_file_request(const uint32_t file_id, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_CLOSE);
    microkit_mr_set(1, file_id);

    microkit_dbg_puts("CLIENT: requested to close file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("close", return_code);
    return return_code;
}

fs_result_read_t send_read_file_request(const uint32_t file_id, const size_t length, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    microkit_mr_set(0, OP_READ);
    microkit_mr_set(1, file_id);
    microkit_mr_set(2, length > CLIENT_BUFFER_SIZE ? CLIENT_BUFFER_SIZE : length);

    microkit_dbg_puts("CLIENT: requested to read file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with length: ");
    microkit_dbg_put32((uint32_t)length);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    fs_result_read_t res;
    res.rc =  microkit_mr_get(0);
    debug_print_return_code("read", res.rc);
    res.data_address = &(fs_buffer_base[8]);
    res.bytes_read = ((uint32_t *)fs_buffer_base)[0];
    res.new_cursor_position = ((uint32_t *)(fs_buffer_base))[1];
    return res;
}


fs_result_write_t send_write_file_request(const uint32_t file_id, const size_t length, const uint8_t *data, uint8_t *fs_buffer_base, const int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    microkit_mr_set(0, OP_WRITE);
    microkit_mr_set(1, file_id);
    microkit_mr_set(2, length);

    copy_data_from_buffer(data, fs_buffer_base, length > CLIENT_BUFFER_SIZE ? CLIENT_BUFFER_SIZE : length);

    microkit_dbg_puts("CLIENT: requested to write file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with length: ");
    microkit_dbg_put32((uint32_t)length);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    fs_result_write_t res;
    res.rc = microkit_mr_get(0);
    debug_print_return_code("write", res.rc);
    res.bytes_written = ((uint32_t *)fs_buffer_base)[0];
    res.new_cursor_position = ((uint32_t *)(fs_buffer_base))[1];
    return res;
}


int send_seek_file_request(const uint32_t file_id, const uint32_t position, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    microkit_mr_set(0, OP_SEEK);
    microkit_mr_set(1, file_id);
    microkit_mr_set(2, position);

    microkit_dbg_puts("CLIENT: requested to seek file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: to position: ");
    microkit_dbg_put32(position);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);
    
    const int return_code = microkit_mr_get(0);
    debug_print_return_code("seek", return_code);
    return return_code;
}


int send_delete_entry_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 1);
    microkit_mr_set(0, OP_DELETE);

    microkit_dbg_puts("CLIENT: requested to delete entry: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("delete", return_code);
    return return_code;
}

int send_set_entry_permissions_request(const unsigned char *path, const permissions_t permissions, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_SET_PERMISSIONS);
    microkit_mr_set(1, permissions);

    microkit_dbg_puts("CLIENT: requested to set permissions for entry: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: to permissions: ");
    microkit_dbg_put32((uint32_t)permissions);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("set permissions", return_code);
    return return_code;
}

fs_result_permissions_t send_get_entry_permissions_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    microkit_mr_set(0, OP_GET_PERMISSIONS);
    microkit_dbg_puts("CLIENT: requested to get permissions for entry: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    fs_result_permissions_t res;
    res.rc = microkit_mr_get(0);
    debug_print_return_code("get permissions", res.rc);
    res.permissions = (uint8_t)fs_buffer_base[0];
    microkit_dbg_puts("CLIENT: got permissions: ");
    microkit_dbg_put8(res.permissions);
    microkit_dbg_puts("\n");

    return res;
}

fs_result_size_t send_get_entry_size_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    microkit_mr_set(0, OP_GET_SIZE);
    microkit_dbg_puts("CLIENT: requested to get size for entry: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    fs_result_size_t res;
    res.rc = microkit_mr_get(0);
    debug_print_return_code("get entry size", res.rc);

    res.size = *((uint32_t *)fs_buffer_base);

    microkit_dbg_puts("CLIENT: got entry size: ");
    microkit_dbg_put32(res.size);
    microkit_dbg_puts("\n");

    return res;
}

fs_result_exists_t send_entry_exists_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 1);
    microkit_mr_set(0, OP_EXISTS);

    microkit_dbg_puts("CLIENT: requested to check existence of entry: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);
    fs_result_exists_t res;
    res.rc = microkit_mr_get(0);
    debug_print_return_code("exists", res.rc);

    res.exists = fs_buffer_base[0];
    microkit_dbg_puts("CLIENT: entry existence: ");
    microkit_dbg_put8(res.exists);
    microkit_dbg_puts("\n");

    return res;
}

fs_result_list_t send_list_entries_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    microkit_mr_set(0, OP_LIST);

    microkit_dbg_puts("CLIENT: requested to list entries at \n");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    fs_result_list_t res;
    res.rc = microkit_mr_get(0);
    debug_print_return_code("list", res.rc);
    res.data_address = fs_buffer_base;

    microkit_dbg_puts("CLIENT: listed entries:\n");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");

    return res;
}

// int send_rename_entry_request(const unsigned char *path, const unsigned char *new_name, uint8_t *fs_buffer_base, int channel_id) {
//     microkit_msginfo msg = microkit_msginfo_new(0, 2);

//     microkit_mr_set(0, OP_RENAME);
//     microkit_mr_set(1, file_id);
//     copy_string_from_buffer(new_name, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);

//     microkit_dbg_puts("CLIENT: requested to rename file: ");
//     microkit_dbg_put32(file_id);
//     microkit_dbg_puts("\n");
//     microkit_dbg_puts("CLIENT: to new name: ");
//     microkit_dbg_puts((const char *)fs_buffer_base);
//     microkit_dbg_puts("\n");
//     microkit_ppcall(channel_id, msg);

//     const int return_code = microkit_mr_get(0);
//     debug_print_return_code("rename", return_code);
//     return return_code;
// }

// fs_result_fileid_t send_copy_file_request(const uint32_t source_file_id, const unsigned char *dest_name, uint8_t *fs_buffer_base, int channel_id) {
//     microkit_msginfo msg = microkit_msginfo_new(0, 2);

//     microkit_mr_set(0, OP_COPY);
//     microkit_mr_set(1, source_file_id);
//     copy_string_from_buffer(dest_name, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);

//     microkit_dbg_puts("CLIENT: requested to copy file: ");
//     microkit_dbg_put32(source_file_id);
//     microkit_dbg_puts("\n");
//     microkit_dbg_puts("CLIENT: to new name: ");
//     microkit_dbg_puts((const char *)fs_buffer_base);
//     microkit_dbg_puts("\n");
//     microkit_ppcall(channel_id, msg);

//     const int return_code = microkit_mr_get(0);
//     debug_print_return_code("copy", return_code);

//     fs_result_fileid_t res;
//     res.rc = return_code;
//     res.file_id = *((uint32_t *)fs_buffer_base);
//     return res;
// }
// move