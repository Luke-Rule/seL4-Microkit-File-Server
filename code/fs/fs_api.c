#include <microkit.h>
#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_api.h"
#include "fs_buffer_manager.h"
#include "fs_queue_manager_client.h"

#define FILE_SERVER_CHANNEL_ID 0

// ------------------------ Debug functions -------------------------- //

void debug_print_return_code(const char *operation, int return_code) {
    microkit_debug_puts("CLIENT: ");
    microkit_debug_puts(operation);
    microkit_debug_puts(" operation returned code: ");
    switch (return_code)
    {
        case FS_OK:
            microkit_debug_puts("FS_OK: Operation completed successfully.\n");
            break;
        case FS_ERR_INODE_TABLE_FULL:
            microkit_debug_puts("FS_ERR_INODE_TABLE_FULL: No more inodes available.\n");
            break;
        case FS_ERR_FILE_DESCRIPTOR_NOT_FOUND:
            microkit_debug_puts("FS_ERR_FILE_DESCRIPTOR_NOT_FOUND: File descriptor not found.\n");
            break;
        case FS_ERR_NO_BLOCKS_REMAINING:
            microkit_debug_puts("FS_ERR_NO_BLOCKS_REMAINING: No more blocks available.\n");
            break;
        case FS_ERR_INVALID_PATH:
            microkit_debug_puts("FS_ERR_INVALID_PATH: The specified path is invalid.\n");
            break;
        case FS_ERR_ALREADY_EXISTS:
            microkit_debug_puts("FS_ERR_ALREADY_EXISTS: The file or directory already exists.\n");
            break;
        case FS_ERR_NOT_FOUND:
            microkit_debug_puts("FS_ERR_NOT_FOUND: The specified file or directory was not found.\n");
            break;
        case FS_ERR_PERMISSION:
            microkit_debug_puts("FS_ERR_PERMISSION: Permission denied for the requested operation.\n");
            break;
        case FS_ERR_OUT_OF_BOUNDS:
            microkit_debug_puts("FS_ERR_OUT_OF_BOUNDS: Operation attempted out-of-bounds access.\n");
            break;
        case FS_ERR_INVALID_OP_CODE:
            microkit_debug_puts("FS_ERR_INVALID_OP_CODE: The operation code is invalid.\n");
            break;
        case FS_ERR_INCORRECT_OP_PARAM_COUNT:
            microkit_debug_puts("FS_ERR_INCORRECT_OP_PARAM_COUNT: Incorrect number of parameters for the operation.\n");
            break;
        case FS_ERR_UNSPECIFIED_ERROR:
            microkit_debug_puts("FS_ERR_UNSPECIFIED_ERROR: An unspecified error occurred.\n");
            break;
        case FS_ERR_BUFFER_TOO_SMALL:
            microkit_debug_puts("FS_ERR_BUFFER_TOO_SMALL: The provided buffer is too small.\n");
            break;
        case FS_ERR_MAX_OPEN_FILES_REACHED:
            microkit_debug_puts("FS_ERR_MAX_OPEN_FILES_REACHED: Maximum number of open files reached.\n");
            break;
        case FS_ERR_MAX_FILE_SIZE_REACHED:
            microkit_debug_puts("FS_ERR_MAX_FILE_SIZE_REACHED: Maximum file size reached.\n");
            break;
        case FS_ERR_MAX_DIR_SIZE_REACHED:
            microkit_debug_puts("FS_ERR_MAX_DIR_SIZE_REACHED: Maximum directory size reached.\n");
            break;
        default:
            microkit_debug_puts("Unknown error code.\n");
            break;
    }
}

// ------------------------------ File system interface functions ------------------------------- //

void notify_file_server(client_t *client_data, int wait_for_completion) {
    client_data->flags.ready_flag = 1;
    // this will do the same thing unless the fs has no budget left
    if (wait_for_completion) {
        microkit_ppcall(FILE_SERVER_CHANNEL_ID, seL4_MessageInfo_new(0, 0, 0, 0));
    } else {
        microkit_notify(FILE_SERVER_CHANNEL_ID);
    }
}

void set_free_completion_buffer(client_t *client_data, int buffer_index) {
    if (buffer_index < 0 || buffer_index >= NUMBER_OF_BUFFERS_PER_CLIENT) {
        return;
    }
    client_data->completion_buffer_table[buffer_index] = 0;
}

int get_next_completion_entry(client_t *client_data, completion_queue_entry_t *out) {
    if (client_data->completion_queue_head == client_data->completion_queue_tail) {
        return FS_ERROR_NO_COMPLETION_ENTRIES_AVAILABLE;
    }
    completion_queue_entry_t *entry = &client_data->completion_queue[client_data->completion_queue_head];
    microkit_debug_puts("CLIENT: fetched completion entry at head index: ");
    microkit_debug_put32(client_data->completion_queue_head);
    microkit_debug_putc('\n');
    increment_completion_queue_head(&client_data->completion_queue_head);
    *out = *entry;
    debug_print_return_code("completion entry", entry->return_code);
    return FS_OK;
}

// ------------------------------ File system operation functions ------------------------------- //

fs_result_t send_create_file_request(const unsigned char *file_name, const permissions_t permissions, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(file_name, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }
    microkit_debug_puts("CLIENT: requested to create file: ");
    microkit_debug_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_debug_puts("\n");
    microkit_debug_puts("CLIENT: with permissions: ");
    microkit_debug_put32((uint32_t)permissions);
    microkit_debug_puts("\n");
    add_submission_entry(OP_CREATE_FILE, permissions, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_create_directory_request(const unsigned char *dir_name, const permissions_t permissions, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(dir_name, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_debug_puts("CLIENT: requested to create directory: ");
    microkit_debug_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_debug_puts("\n");
    microkit_debug_puts("CLIENT: with permissions: ");
    microkit_debug_put32((uint32_t)permissions);
    microkit_debug_puts("\n");
    add_submission_entry(OP_CREATE_DIRECTORY, permissions, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_open_file_request(const file_open_operations_t ops, const unsigned char *file_name, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(file_name, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }
    microkit_debug_puts("CLIENT: requested to open file: ");
    microkit_debug_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_debug_puts("\n");
    add_submission_entry(OP_OPEN, ops, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_close_file_request(const uint32_t file_id, client_t *client_data) {
    microkit_debug_puts("CLIENT: requested to close file: ");
    microkit_debug_put32(file_id);
    microkit_debug_puts("\n");
    add_submission_entry(OP_CLOSE, 0, file_id, client_data, -1);
    return FS_OK;
}

fs_result_t send_read_file_request(const uint32_t file_id, const uint32_t length, client_t *client_data) {
    microkit_debug_puts("CLIENT: requested to read file: ");
    microkit_debug_put32(file_id);
    microkit_debug_puts("\n");
    microkit_debug_puts("CLIENT: with length: ");
    microkit_debug_put32((uint32_t)length);
    microkit_debug_puts("\n");
    add_submission_entry(OP_READ, file_id, length < CLIENT_BUFFER_SIZE ? length : CLIENT_BUFFER_SIZE, client_data, -1);
    return FS_OK;
}


fs_result_t send_write_file_request(const uint32_t file_id, const size_t length, const uint8_t *data, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_data_to_submission_buffer(data, length, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_debug_puts("CLIENT: requested to write file: ");
    microkit_debug_put32(file_id);
    microkit_debug_puts("\n");
    microkit_debug_puts("CLIENT: with length: ");
    microkit_debug_put32((uint32_t)length);
    microkit_debug_puts("\n");

    add_submission_entry(OP_WRITE, file_id, length < CLIENT_BUFFER_SIZE ? length : CLIENT_BUFFER_SIZE, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_seek_file_request(const uint32_t file_id, const uint32_t position, client_t *client_data) {
    microkit_debug_puts("CLIENT: requested to seek file: ");
    microkit_debug_put32(file_id);
    microkit_debug_puts("\n");
    microkit_debug_puts("CLIENT: to position: ");
    microkit_debug_put32(position);
    microkit_debug_puts("\n");
    add_submission_entry(OP_SEEK, file_id, position, client_data, -1);
    return FS_OK;
}


fs_result_t send_delete_entry_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }
    microkit_debug_puts("CLIENT: requested to delete entry: ");
    microkit_debug_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_debug_puts("\n");
    add_submission_entry(OP_DELETE, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_set_entry_permissions_request(const unsigned char *path, const permissions_t permissions, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }
    microkit_debug_puts("CLIENT: requested to set permissions for entry: ");
    microkit_debug_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_debug_puts("\n");
    microkit_debug_puts("CLIENT: to permissions: ");
    microkit_debug_put32((uint32_t)permissions);
    microkit_debug_puts("\n");

    add_submission_entry(OP_SET_PERMISSIONS, permissions, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_get_entry_permissions_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_debug_puts("CLIENT: requested to get permissions for entry: ");
    microkit_debug_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_debug_puts("\n");

    add_submission_entry(OP_GET_PERMISSIONS, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_get_entry_size_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_debug_puts("CLIENT: requested to get size for entry: ");
    microkit_debug_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_debug_puts("\n");

    add_submission_entry(OP_GET_SIZE, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_entry_exists_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_debug_puts("CLIENT: requested to check existence of entry: ");
    microkit_debug_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_debug_puts("\n");
    add_submission_entry(OP_EXISTS, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_list_entries_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_debug_puts("CLIENT: requested to list entries at \n");
    microkit_debug_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_debug_puts("\n");

    add_submission_entry(OP_LIST, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}
