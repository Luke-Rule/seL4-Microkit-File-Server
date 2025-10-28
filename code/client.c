#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include "definitions.h"
#include "utils.c"

#define FILE_SERVER_CHANNEL_ID 0

uint8_t *file_server_buffer_base;

void notified(microkit_channel client_id) {}

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
            break;
    }
}

uint32_t get_returned_file_id(void) {
    uint32_t file_id = 0;
    file_id |= (file_server_buffer_base[0] << 0);
    file_id |= (file_server_buffer_base[1] << 8);
    file_id |= (file_server_buffer_base[2] << 16);
    file_id |= (file_server_buffer_base[3] << 24);
    return file_id;
}


uint32_t send_create_file_request(const unsigned char *file_name, const uint32_t size, const file_permission_t permissions) {
    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    copy_string_from_buffer(file_name, (unsigned char *)file_server_buffer_base, MAX_FILE_NAME_LENGTH);

    microkit_mr_set(0, OP_CREATE);
    microkit_mr_set(1, size);
    microkit_mr_set(2, permissions);

    microkit_dbg_puts("CLIENT: requested to create file: ");
    microkit_dbg_puts((const char *)file_server_buffer_base);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with size: ");
    microkit_dbg_put32(size);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: and permissions: ");
    microkit_dbg_put32((uint32_t)permissions);
    microkit_dbg_puts("\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("create", return_code);
    return get_returned_file_id();
}


uint32_t send_open_file_request(const unsigned char *file_name) {
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    copy_string_from_buffer(file_name, (unsigned char *)file_server_buffer_base, MAX_FILE_NAME_LENGTH);

    microkit_mr_set(0, OP_OPEN);

    microkit_dbg_puts("CLIENT: requested to open file: ");
    microkit_dbg_puts((const char *)file_server_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("open", return_code);
    return get_returned_file_id();
}


void send_close_file_request(const uint32_t file_id) {}


unsigned char * send_read_file_request(const uint32_t file_id, const uint32_t offset, const size_t length) {
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
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("read", return_code);

    microkit_dbg_puts("CLIENT: read data: \n");
    for (size_t i = 0; i < length; i++) {
        // check bounds
        if (i >= CLIENT_BUFFER_SIZE) {
            break;
        }
        microkit_dbg_puts((const char *)&file_server_buffer_base[i]);
    }
    microkit_dbg_puts("\n");
    return file_server_buffer_base;
}


void send_write_file_request(const uint32_t file_id, const uint32_t offset, const size_t length) {
    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    microkit_mr_set(0, OP_WRITE);
    microkit_mr_set(1, file_id);
    microkit_mr_set(2, offset);
    microkit_mr_set(3, length);

    microkit_dbg_puts("CLIENT: requested to write file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with offset: ");
    microkit_dbg_put32(offset);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: and length: ");
    microkit_dbg_put32((uint32_t)length);
    microkit_dbg_puts("\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("write", return_code);
}

void send_delete_file_request(const uint32_t file_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    microkit_mr_set(0, OP_DELETE);
    microkit_mr_set(1, file_id);

    microkit_dbg_puts("CLIENT: requested to delete file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("delete", return_code);
}

void send_list_files_request(void) {
    microkit_msginfo msg = microkit_msginfo_new(0, 0);

    microkit_mr_set(0, OP_LIST);

    microkit_dbg_puts("CLIENT: requested to list files\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("list", return_code);

    microkit_dbg_puts("CLIENT: listed files:\n");
    microkit_dbg_puts((const char *)file_server_buffer_base);
    microkit_dbg_puts("\n");
}

void send_set_file_permissions_request(const uint32_t file_id, const file_permission_t permissions) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_SET_PERMISSIONS);
    microkit_mr_set(1, file_id);
    microkit_mr_set(2, permissions);

    microkit_dbg_puts("CLIENT: requested to set permissions for file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: to permissions: ");
    microkit_dbg_put32((uint32_t)permissions);
    microkit_dbg_puts("\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("set permissions", return_code);
}

uint8_t send_get_file_permissions_request(const uint32_t file_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    microkit_mr_set(0, OP_GET_PERMISSIONS);
    microkit_mr_set(1, file_id);

    microkit_dbg_puts("CLIENT: requested to get permissions for file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("get permissions", return_code);

    uint8_t permissions = (uint8_t)file_server_buffer_base[0];
    microkit_dbg_puts("CLIENT: got permissions: ");
    microkit_dbg_put8(permissions);
    microkit_dbg_puts("\n");

    return permissions;
}

void send_rename_file_request(const uint32_t file_id, const unsigned char *new_name) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_RENAME);
    microkit_mr_set(1, file_id);
    copy_string_from_buffer(new_name, (unsigned char *)file_server_buffer_base, MAX_FILE_NAME_LENGTH);

    microkit_dbg_puts("CLIENT: requested to rename file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: to new name: ");
    microkit_dbg_puts((const char *)file_server_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("rename", return_code);
}

uint32_t send_get_file_size_request(const uint32_t file_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    microkit_mr_set(0, OP_GET_FILE_SIZE);
    microkit_mr_set(1, file_id);

    microkit_dbg_puts("CLIENT: requested to get size for file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("get file size", return_code);

    uint32_t file_size = 0;
    file_size |= (file_server_buffer_base[0] << 0);
    file_size |= (file_server_buffer_base[1] << 8);
    file_size |= (file_server_buffer_base[2] << 16);
    file_size |= (file_server_buffer_base[3] << 24);

    microkit_dbg_puts("CLIENT: got file size: ");
    microkit_dbg_put32(file_size);
    microkit_dbg_puts("\n");

    return file_size;
}

uint8_t send_file_exists_request(const unsigned char *file_name) {
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    copy_string_from_buffer(file_name, (unsigned char *)file_server_buffer_base, MAX_FILE_NAME_LENGTH);

    microkit_mr_set(0, OP_EXISTS);

    microkit_dbg_puts("CLIENT: requested to check existence of file: ");
    microkit_dbg_puts((const char *)file_server_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("exists", return_code);

    const uint8_t exists = file_server_buffer_base[0];
    microkit_dbg_puts("CLIENT: file existence: ");
    microkit_dbg_put8(exists);
    microkit_dbg_puts("\n");

    return exists;
}

uint32_t send_copy_file_request(const uint32_t source_file_id, const unsigned char *dest_name) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_COPY);
    microkit_mr_set(1, source_file_id);
    copy_string_from_buffer(dest_name, (unsigned char *)file_server_buffer_base, MAX_FILE_NAME_LENGTH);

    microkit_dbg_puts("CLIENT: requested to copy file: ");
    microkit_dbg_put32(source_file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: to new name: ");
    microkit_dbg_puts((const char *)file_server_buffer_base);
    microkit_dbg_puts("\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    const int return_code = microkit_mr_get(0);
    debug_print_return_code("copy", return_code);
    return get_returned_file_id();
}

void init(void) {
    microkit_dbg_puts("CLIENT: started\n");

    send_create_file_request(
        (const unsigned char *)"hello.txt", 1024, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE
    );
}
