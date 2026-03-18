#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../debug_output.h"

#include "include/fs_api.h"
#include "include/fs_buffer_manager.h"
#include "include/fs_queue_manager_client.h"

// ------------------------ Benchmarking and debug functions -------------------------- //

void mark_client_as_finished_running(client_t *client_data) {
    client_data->flags.finished_running_flag = true;
}

void debug_print_return_code(const char *operation, const uint8_t return_code) {
    microkit_debug_puts(OUTPUT_VERBOSITY, "CLIENT: ");
    microkit_debug_puts(OUTPUT_VERBOSITY, operation);
    microkit_debug_puts(OUTPUT_VERBOSITY, " operation returned code: ");
    switch (return_code)
    {
        case FS_OK:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_OK: Operation completed successfully.\n");
            break;
        case FS_ERR_INODE_TABLE_FULL:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_INODE_TABLE_FULL: No more inodes available.\n");
            break;
        case FS_ERR_FILE_DESCRIPTOR_NOT_FOUND:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_FILE_DESCRIPTOR_NOT_FOUND: File descriptor not found.\n");
            break;
        case FS_ERR_NO_BLOCKS_REMAINING:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_NO_BLOCKS_REMAINING: No more blocks available.\n");
            break;
        case FS_ERR_INVALID_PATH:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_INVALID_PATH: The specified path is invalid.\n");
            break;
        case FS_ERR_ALREADY_EXISTS:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_ALREADY_EXISTS: The file or directory already exists.\n");
            break;
        case FS_ERR_NOT_FOUND:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_NOT_FOUND: The specified file or directory was not found.\n");
            break;
        case FS_ERR_PERMISSION:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_PERMISSION: Permission denied for the requested operation.\n");
            break;
        case FS_ERR_OUT_OF_BOUNDS:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_OUT_OF_BOUNDS: Operation attempted out-of-bounds access.\n");
            break;
        case FS_ERR_INVALID_OP_CODE:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_INVALID_OP_CODE: The operation code is invalid.\n");
            break;
        case FS_ERR_INCORRECT_OP_PARAM_COUNT:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_INCORRECT_OP_PARAM_COUNT: Incorrect number of parameters for the operation.\n");
            break;
        case FS_ERR_UNSPECIFIED_ERROR:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_UNSPECIFIED_ERROR: An unspecified error occurred.\n");
            break;
        case FS_ERR_BUFFER_TOO_SMALL:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_BUFFER_TOO_SMALL: The provided buffer is too small.\n");
            break;
        case FS_ERR_MAX_OPEN_FILES_REACHED:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_MAX_OPEN_FILES_REACHED: Maximum number of open files reached.\n");
            break;
        case FS_ERR_MAX_FILE_SIZE_REACHED:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_MAX_FILE_SIZE_REACHED: Maximum file size reached.\n");
            break;
        case FS_ERR_MAX_DIR_SIZE_REACHED:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FS_ERR_MAX_DIR_SIZE_REACHED: Maximum directory size reached.\n");
            break;
        default:
            microkit_debug_puts(OUTPUT_VERBOSITY, "Unknown error code.\n");
            break;
    }
}

// ------------------------------ File system interface functions ------------------------------- //

void notify_file_server(client_t *client_data, const bool wait_for_completion) {
    // the fs will only service a client if its ready flag is set, so clients can batch requests
    client_data->flags.ready_flag = true;
    client_data->flags.complete_flag = false;
    // this will do the same thing unless the fs has no budget left
    if (wait_for_completion) {
        microkit_ppcall(FILE_SERVER_CHANNEL_ID, seL4_MessageInfo_new(0, 0, 0, 0));
    } else {
        microkit_notify(FILE_SERVER_CHANNEL_ID);
    }
}

bool get_if_any_operations_completed(client_t *client_data) {
    return client_data->flags.complete_flag;
}

// These are required as the FS limits ops per service to prevent starvation of other clients
uint8_t get_number_of_completed_operations(client_t *client_data) {
    if (client_data->completion_queue_tail >= client_data->completion_queue_head) {
        return client_data->completion_queue_tail - client_data->completion_queue_head;
    } else {
        return MAX_QUEUE_ENTRIES - (client_data->completion_queue_head - client_data->completion_queue_tail);
    }
}

void wait_until_n_operations_completed(client_t *client_data, const size_t n) {
    while (get_number_of_completed_operations(client_data) < n) {
        notify_file_server(client_data, BLOCK_ON_NOTIFY);
    }
}

void notify_file_server_and_wait_for_all_operations(client_t *client_data, const size_t number_of_operations) {
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    wait_until_n_operations_completed(client_data, number_of_operations);
}

// called by client when results from requests have been processed
void set_free_completion_buffer(client_t *client_data, const size_t buffer_index) {
    if (buffer_index >= NUMBER_OF_BUFFERS_PER_CLIENT) {
        return;
    }

    client_data->completion_buffer_table[buffer_index] = false;
}

fs_result_t get_next_completion_entry(client_t *client_data, completion_queue_entry_t *out) {
    if (client_data->completion_queue_head == client_data->completion_queue_tail) {
        return FS_ERROR_NO_COMPLETION_ENTRIES_AVAILABLE;
    }

    completion_queue_entry_t *entry = &client_data->completion_queue[client_data->completion_queue_head];
    increment_queue_pointer(&client_data->completion_queue_head);
    *out = *entry;

    return FS_OK;
}

// ---------- File system operation functions, wrappers for adding to submission queue ----------//

fs_result_t send_create_file_request(const unsigned char *file_name, const permissions_t permissions, const file_open_operations_t operations, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(file_name, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    add_submission_entry(OP_CREATE_FILE, permissions, operations, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_create_directory_request(const unsigned char *dir_name, const permissions_t permissions, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(dir_name, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    add_submission_entry(OP_CREATE_DIRECTORY, permissions, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_open_file_request(const unsigned char *file_name, const file_open_operations_t ops, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(file_name, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    add_submission_entry(OP_OPEN, ops, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_close_file_request(const uint32_t file_id, client_t *client_data) {
    add_submission_entry(OP_CLOSE, file_id, 0, client_data, SIZE_MAX);
    return FS_OK;
}

fs_result_t send_read_file_request(const uint32_t file_id, const size_t length, client_t *client_data) {
    add_submission_entry(OP_READ, file_id, length < CLIENT_BUFFER_SIZE ? length : CLIENT_BUFFER_SIZE, client_data, SIZE_MAX);
    return FS_OK;
}


fs_result_t send_write_file_request(const uint32_t file_id, const size_t length, const uint8_t *data, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_data_to_submission_buffer(data, length, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    add_submission_entry(OP_WRITE, file_id, length < CLIENT_BUFFER_SIZE ? length : CLIENT_BUFFER_SIZE, client_data, copy_result.buffer_index);
    return FS_OK;
}


fs_result_t send_seek_file_request(const uint32_t file_id, const uint32_t position, client_t *client_data) {
    add_submission_entry(OP_SEEK, file_id, position, client_data, SIZE_MAX);
    return FS_OK;
}


fs_result_t send_delete_entry_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    add_submission_entry(OP_DELETE, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_set_entry_permissions_request(const unsigned char *path, const permissions_t permissions, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    add_submission_entry(OP_SET_PERMISSIONS, permissions, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_get_entry_permissions_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    add_submission_entry(OP_GET_PERMISSIONS, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_get_entry_size_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    add_submission_entry(OP_GET_SIZE, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_entry_exists_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    add_submission_entry(OP_EXISTS, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}

fs_result_t send_list_entries_request(const unsigned char *path, client_t *client_data) {
    buffer_copy_result_t copy_result = copy_string_to_submission_buffer(path, client_data);
    if (copy_result.rc != FS_OK) {
        return copy_result.rc;
    }

    add_submission_entry(OP_LIST, 0, 0, client_data, copy_result.buffer_index);
    return FS_OK;
}
