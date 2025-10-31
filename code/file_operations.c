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


void debug_print_return_code(const char *operation, int return_code) {
    microkit_dbg_puts("CLIENT: ");
    microkit_dbg_puts(operation);
    microkit_dbg_puts(" operation returned code: ");
    switch (return_code)
    {
        case FS_OK:
            microkit_dbg_puts("FS_OK: Operation completed successfully.\n");
            break;
        case FS_ERR_TABLE_FULL:
            microkit_dbg_puts("FS_ERR_TABLE_FULL: The file table is full.\n");
            break;
        case FS_ERR_FILE_EXCEEDS_MAX_SIZE:
            microkit_dbg_puts("FS_ERR_FILE_EXCEEDS_MAX_SIZE: The file exceeds the maximum allowed size.\n");
            break;
        case FS_ERR_FILE_EXCEEDS_REMAINING_SPACE:
            microkit_dbg_puts("FS_ERR_FILE_EXCEEDS_REMAINING_SPACE: The file exceeds the remaining storage space.\n");
            break;
        case FS_ERR_INVALID_NAME:
            microkit_dbg_puts("FS_ERR_INVALID_NAME: The provided file name is invalid.\n");
            break;
        case FS_ERR_ALREADY_EXISTS:
            microkit_dbg_puts("FS_ERR_ALREADY_EXISTS: A file with the same name already exists.\n");
            break;
        case FS_ERR_NOT_FOUND:
            microkit_dbg_puts("FS_ERR_NOT_FOUND: The specified file was not found.\n");
            break;
        case FS_ERR_PERMISSION:
            microkit_dbg_puts("FS_ERR_PERMISSION: Permission denied for the requested operation.\n");
            break;
        case FS_ERR_OUT_OF_BOUNDS:
            microkit_dbg_puts("FS_ERR_OUT_OF_BOUNDS: The operation attempted to access data out of bounds.\n");
            break;
        case FS_ERR_NAME_COLLISION:
            microkit_dbg_puts("FS_ERR_NAME_COLLISION: A name collision occurred during the operation.\n");
            break;
        case FS_ERR_INVALID_OP_CODE:
            microkit_dbg_puts("FS_ERR_INVALID_OP_CODE: The provided operation code is invalid.\n");
            break;
        case FS_ERR_INCORRECT_OP_PARAM_COUNT:
            microkit_dbg_puts("FS_ERR_INCORRECT_OP_PARAM_COUNT: The number of operation parameters is incorrect.\n");
            break;
        case FS_ERR_UNSPECIFIED_ERROR:
            microkit_dbg_puts("FS_ERR_UNSPECIFIED_ERROR: An unspecified error occurred during the operation.\n");
            break;
        default:
            microkit_dbg_puts("Unknown error code.\n");
            break;
    }
}


fs_result_fileid_t send_create_file_request(const unsigned char *file_name, const uint32_t size, const file_permission_t permissions, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    copy_string_from_buffer(file_name, (unsigned char *)fs_buffer_base, MAX_FILE_NAME_LENGTH);

    microkit_mr_set(0, OP_CREATE);
    microkit_mr_set(1, size);
    microkit_mr_set(2, permissions);

    microkit_dbg_puts("CLIENT: requested to create file: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with size: ");
    microkit_dbg_put32(size);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: and permissions: ");
    microkit_dbg_put32((uint32_t)permissions);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("create", return_code);

    fs_result_fileid_t res;
    res.rc = return_code;
    res.file_id = *((uint32_t *)fs_buffer_base);
    return res;
}


fs_result_fileid_t send_open_file_request(const unsigned char *file_name, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    copy_string_from_buffer(file_name, (unsigned char *)fs_buffer_base, MAX_FILE_NAME_LENGTH);

    microkit_mr_set(0, OP_OPEN);

    microkit_dbg_puts("CLIENT: requested to open file: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("open", return_code);

    fs_result_fileid_t res;
    res.rc = return_code;
    res.file_id = *((uint32_t *)fs_buffer_base);
    return res;
}


void send_close_file_request(const uint32_t file_id, uint8_t *fs_buffer_base, int channel_id) {}


int send_read_file_request(const uint32_t file_id, const uint32_t offset, const size_t length, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    microkit_mr_set(0, OP_READ);
    microkit_mr_set(1, file_id);
    microkit_mr_set(2, offset);
    microkit_mr_set(3, length);

    microkit_dbg_puts("CLIENT: requested to read file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with offset: ");
    microkit_dbg_put32(offset);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: and length: ");
    microkit_dbg_put32((uint32_t)length);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("read", return_code);

    microkit_dbg_puts("CLIENT: read data: \n");
    for (size_t i = 0; i < length; i++) {
        /* check bounds */
        if (i >= CLIENT_BUFFER_SIZE) {
            break;
        }
        microkit_dbg_puts((const char *)&fs_buffer_base[i]);
    }
    microkit_dbg_puts("\n");

    return return_code;
}


int send_write_file_request(const uint32_t file_id, const uint32_t offset, const size_t length, uint8_t *data, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 4);

    microkit_mr_set(0, OP_WRITE);
    microkit_mr_set(1, file_id);
    microkit_mr_set(2, offset);
    microkit_mr_set(3, length);
    copy_data_from_buffer(data, fs_buffer_base, length);

    microkit_dbg_puts("CLIENT: requested to write file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with offset: ");
    microkit_dbg_put32(offset);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: and length: ");
    microkit_dbg_put32((uint32_t)length);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("write", return_code);
    return return_code;
}

int send_delete_file_request(const uint32_t file_id, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_DELETE);
    microkit_mr_set(1, file_id);

    microkit_dbg_puts("CLIENT: requested to delete file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("delete", return_code);
    return return_code;
}

int send_list_files_request(uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    microkit_mr_set(0, OP_LIST);

    microkit_dbg_puts("CLIENT: requested to list files\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("list", return_code);

    microkit_dbg_puts("CLIENT: listed files:\n");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");

    return return_code;
}

int send_set_file_permissions_request(const uint32_t file_id, const file_permission_t permissions, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    microkit_mr_set(0, OP_SET_PERMISSIONS);
    microkit_mr_set(1, file_id);
    microkit_mr_set(2, permissions);

    microkit_dbg_puts("CLIENT: requested to set permissions for file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: to permissions: ");
    microkit_dbg_put32((uint32_t)permissions);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("set permissions", return_code);
    return return_code;
}

fs_result_permissions_t send_get_file_permissions_request(const uint32_t file_id, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_GET_PERMISSIONS);
    microkit_mr_set(1, file_id);

    microkit_dbg_puts("CLIENT: requested to get permissions for file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("get permissions", return_code);

    uint8_t permissions = (uint8_t)fs_buffer_base[0];
    microkit_dbg_puts("CLIENT: got permissions: ");
    microkit_dbg_put8(permissions);
    microkit_dbg_puts("\n");

    fs_result_permissions_t res;
    res.rc = return_code;
    res.permissions = permissions;
    return res;
}

int send_rename_file_request(const uint32_t file_id, const unsigned char *new_name, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_RENAME);
    microkit_mr_set(1, file_id);
    copy_string_from_buffer(new_name, (unsigned char *)fs_buffer_base, MAX_FILE_NAME_LENGTH);

    microkit_dbg_puts("CLIENT: requested to rename file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: to new name: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("rename", return_code);
    return return_code;
}

fs_result_size_t send_get_file_size_request(const uint32_t file_id, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_GET_FILE_SIZE);
    microkit_mr_set(1, file_id);

    microkit_dbg_puts("CLIENT: requested to get size for file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("get file size", return_code);

    uint32_t file_size = *((uint32_t *)fs_buffer_base);

    microkit_dbg_puts("CLIENT: got file size: ");
    microkit_dbg_put32(file_size);
    microkit_dbg_puts("\n");

    fs_result_size_t res;
    res.rc = return_code;
    res.size = file_size;
    return res;
}

fs_result_exists_t send_file_exists_request(const unsigned char *file_name, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    copy_string_from_buffer(file_name, (unsigned char *)fs_buffer_base, MAX_FILE_NAME_LENGTH);

    microkit_mr_set(0, OP_EXISTS);

    microkit_dbg_puts("CLIENT: requested to check existence of file: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("exists", return_code);

    const uint8_t exists = fs_buffer_base[0];
    microkit_dbg_puts("CLIENT: file existence: ");
    microkit_dbg_put8(exists);
    microkit_dbg_puts("\n");

    fs_result_exists_t res;
    res.rc = return_code;
    res.exists = exists;
    return res;
}

fs_result_fileid_t send_copy_file_request(const uint32_t source_file_id, const unsigned char *dest_name, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_COPY);
    microkit_mr_set(1, source_file_id);
    copy_string_from_buffer(dest_name, (unsigned char *)fs_buffer_base, MAX_FILE_NAME_LENGTH);

    microkit_dbg_puts("CLIENT: requested to copy file: ");
    microkit_dbg_put32(source_file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: to new name: ");
    microkit_dbg_puts((const char *)fs_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("copy", return_code);

    fs_result_fileid_t res;
    res.rc = return_code;
    res.file_id = *((uint32_t *)fs_buffer_base);
    return res;
}