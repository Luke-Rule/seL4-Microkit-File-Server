#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "definitions.h"

#define FILE_SERVER_CHANNEL_ID 0

// ------------------------ Parameter Structs -------------------------- //

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

struct buffer_copy_result {
    uint8_t buffer_index;
    fs_result_t rc;
} typedef buffer_copy_result_t;

// ------------------------ Debug functions -------------------------- //

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

// ------------------------ Buffer management functions -------------------------- //

int get_free_submission_buffer(uint8_t *buffer_table) {
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        if (buffer_table[i] == 0) {
            buffer_table[i] = 1;
            return i;
        }
    }
    return -1;
}


void set_free_completion_buffer(int buffer_index, uint8_t *buffer_table) {
    if (buffer_index < 0 || buffer_index >= NUMBER_OF_BUFFERS_PER_CLIENT) {
        return;
    }
    buffer_table[buffer_index] = 0;
}

// ------------------------------ Buffer data management functions ------------------------------- //

buffer_copy_result_t copy_string_from_buffer(const unsigned char *src, client_t *client_data) {
    buffer_copy_result_t result;
    int buffer_index = get_free_submission_buffer(client_data->submission_buffer_table);
    if (buffer_index == -1) {
        result.rc = FS_ERROR_NO_FREE_SUBMISSION_BUFFERS;
        result.buffer_index = -1;
        return result;
    }
    microkit_dbg_puts("CLIENT: copying string to submission buffer at index ");
    microkit_dbg_put32(buffer_index);
    microkit_dbg_puts("\n");
    unsigned char *dest = &client_data->submission_buffers[buffer_index].data[0];
    size_t i;
    for (i = 0; i < CLIENT_BUFFER_SIZE - 1; i++) {
        dest[i] = src[i];
        if (dest[i] == '\0') {
            result.rc = FS_OK;
            break;
        }
    }
    if (dest[i] != '\0') {
        dest[CLIENT_BUFFER_SIZE - 1] = '\0';
        result.rc = FS_ERR_BUFFER_TOO_SMALL;
    }
    microkit_dbg_puts("CLIENT: copied string: ");
    microkit_dbg_puts((const char *)&client_data->submission_buffers[buffer_index].data[0]);
    microkit_dbg_puts("\n");
    result.buffer_index = buffer_index;
    return result;
}


buffer_copy_result_t copy_data_from_buffer(const uint8_t *src, const size_t length, client_t *client_data) {
    buffer_copy_result_t result;
    int buffer_index = get_free_submission_buffer(client_data->submission_buffer_table);
    if (buffer_index == -1) {
        result.rc = FS_ERROR_NO_FREE_SUBMISSION_BUFFERS;
        result.buffer_index = -1;
        return result;
    }
    uint8_t *dest = &client_data->submission_buffers[buffer_index].data[0];
    for (size_t i = 0; i < (length < CLIENT_BUFFER_SIZE ? length : CLIENT_BUFFER_SIZE); i++) {
        dest[i] = src[i];
    }
    result.rc = FS_OK;
    result.buffer_index = buffer_index;
    return result;
}

// ------------------------------- Queue management functions ------------------------------- //

void increment_submission_queue_tail(uint32_t *submission_queue_tail) {
    microkit_dbg_puts("incrementing submission queue tail\n");
    if (*submission_queue_tail >= MAX_QUEUE_ENTRIES - 1) {
        // already checked theres space
        *submission_queue_tail = 1;
        return;
    }
    *submission_queue_tail = (*submission_queue_tail + 1);
}


void increment_completion_queue_head(uint32_t *completion_queue_head) {
    if (*completion_queue_head >= MAX_QUEUE_ENTRIES - 1) {
        *completion_queue_head = 1;
        return;
    }
    *completion_queue_head = (*completion_queue_head + 1);
}


void add_submission_entry(uint8_t operation_code, uint32_t parameter1, uint32_t parameter2, client_t *client_data, const int buffer_index) {
    if (client_data->submission_queue_tail + 1 == client_data->submission_queue_head || (client_data->submission_queue_head == 1 && client_data->submission_queue_tail == MAX_QUEUE_ENTRIES - 1)) {
        microkit_dbg_puts("CLIENT: no free submission entries available\n");
        return;
    }
    microkit_dbg_puts("Adding submission entry at tail index: ");
    microkit_dbg_put32(client_data->submission_queue_tail);
    microkit_dbg_putc('\n');
    submission_queue_entry_t new_entry;
    new_entry.operation_code = operation_code;
    new_entry.parameter1 = parameter1;
    new_entry.parameter2 = parameter2;
    new_entry.buffer_index = buffer_index;
    client_data->submission_queue[client_data->submission_queue_tail] = new_entry;
    increment_submission_queue_tail(&client_data->submission_queue_tail);
}


int get_next_completion_entry(client_t *client_data, completion_queue_entry_t *out) {
    if (client_data->completion_queue_head == client_data->completion_queue_tail) {
        return FS_ERROR_NO_COMPLETION_ENTRIES_AVAILABLE;
    }
    completion_queue_entry_t *entry = &client_data->completion_queue[client_data->completion_queue_head];
    microkit_dbg_puts("CLIENT: fetched completion entry at head index: ");
    microkit_dbg_put32(client_data->completion_queue_head);
    microkit_dbg_putc('\n');
    increment_completion_queue_head(&client_data->completion_queue_head);
    *out = *entry;
    debug_print_return_code("completion entry", entry->return_code);
    return FS_OK;
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

// ------------------------------ File system operation functions ------------------------------- //

fs_result_t send_create_file_request(const unsigned char *file_name, const permissions_t permissions, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_from_buffer(file_name, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }
    microkit_dbg_puts("CLIENT: requested to create file: ");
    microkit_dbg_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with permissions: ");
    microkit_dbg_put32((uint32_t)permissions);
    microkit_dbg_puts("\n");
    add_submission_entry(OP_CREATE_FILE, permissions, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_create_directory_request(const unsigned char *dir_name, const permissions_t permissions, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_from_buffer(dir_name, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_dbg_puts("CLIENT: requested to create directory: ");
    microkit_dbg_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with permissions: ");
    microkit_dbg_put32((uint32_t)permissions);
    microkit_dbg_puts("\n");
    add_submission_entry(OP_CREATE_DIRECTORY, permissions, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_open_file_request(const file_open_operations_t ops, const unsigned char *file_name, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_from_buffer(file_name, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }
    microkit_dbg_puts("CLIENT: requested to open file: ");
    microkit_dbg_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_dbg_puts("\n");
    add_submission_entry(OP_OPEN, ops, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_close_file_request(const uint32_t file_id, client_t *client_data) {
    microkit_dbg_puts("CLIENT: requested to close file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    add_submission_entry(OP_CLOSE, 0, file_id, client_data, -1);
    return FS_OK;
}

fs_result_t send_read_file_request(const uint32_t file_id, const uint32_t length, client_t *client_data) {
    microkit_dbg_puts("CLIENT: requested to read file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with length: ");
    microkit_dbg_put32((uint32_t)length);
    microkit_dbg_puts("\n");
    add_submission_entry(OP_READ, file_id, length < CLIENT_BUFFER_SIZE ? length : CLIENT_BUFFER_SIZE, client_data, -1);
    return FS_OK;
}


fs_result_t send_write_file_request(const uint32_t file_id, const size_t length, const uint8_t *data, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_data_from_buffer(data, length, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_dbg_puts("CLIENT: requested to write file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: with length: ");
    microkit_dbg_put32((uint32_t)length);
    microkit_dbg_puts("\n");

    add_submission_entry(OP_WRITE, file_id, length < CLIENT_BUFFER_SIZE ? length : CLIENT_BUFFER_SIZE, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_seek_file_request(const uint32_t file_id, const uint32_t position, client_t *client_data) {
    microkit_dbg_puts("CLIENT: requested to seek file: ");
    microkit_dbg_put32(file_id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: to position: ");
    microkit_dbg_put32(position);
    microkit_dbg_puts("\n");
    add_submission_entry(OP_SEEK, file_id, position, client_data, -1);
    return FS_OK;
}


fs_result_t send_delete_entry_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_from_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }
    microkit_dbg_puts("CLIENT: requested to delete entry: ");
    microkit_dbg_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_dbg_puts("\n");
    add_submission_entry(OP_DELETE, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_set_entry_permissions_request(const unsigned char *path, const permissions_t permissions, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_from_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }
    microkit_dbg_puts("CLIENT: requested to set permissions for entry: ");
    microkit_dbg_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("CLIENT: to permissions: ");
    microkit_dbg_put32((uint32_t)permissions);
    microkit_dbg_puts("\n");

    add_submission_entry(OP_SET_PERMISSIONS, permissions, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_get_entry_permissions_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_from_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_dbg_puts("CLIENT: requested to get permissions for entry: ");
    microkit_dbg_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_dbg_puts("\n");

    add_submission_entry(OP_GET_PERMISSIONS, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_get_entry_size_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_from_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_dbg_puts("CLIENT: requested to get size for entry: ");
    microkit_dbg_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_dbg_puts("\n");

    add_submission_entry(OP_GET_SIZE, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_entry_exists_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_from_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_dbg_puts("CLIENT: requested to check existence of entry: ");
    microkit_dbg_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_dbg_puts("\n");
    add_submission_entry(OP_EXISTS, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_list_entries_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_from_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    microkit_dbg_puts("CLIENT: requested to list entries at \n");
    microkit_dbg_puts((const char *)client_data->submission_buffers[copy_result.buffer_index].data);
    microkit_dbg_puts("\n");

    add_submission_entry(OP_LIST, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}
