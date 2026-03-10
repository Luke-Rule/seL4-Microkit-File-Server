#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../debug_output.h"

#include "include/fs_buffer_manager.h"

// ------------------------ Buffer requirement checks -------------------------- //

bool operation_requires_completion_buffer(const operation_t operation) {
    if (operation == OP_READ || operation == OP_LIST || operation == OP_GET_PERMISSIONS ||
        operation == OP_GET_SIZE || operation == OP_EXISTS
    ) {
        return true;
    }

    return false;
}

bool operation_requires_submission_buffer(const operation_t operation) {
    if (operation == OP_CREATE_FILE || operation == OP_CREATE_DIRECTORY || operation == OP_OPEN ||
        operation == OP_WRITE || operation == OP_DELETE || operation == OP_SET_PERMISSIONS ||
        operation == OP_GET_PERMISSIONS || operation == OP_GET_SIZE || operation == OP_EXISTS ||
        operation == OP_LIST
    ) {
        return true;
    }

    return false;
}

// ------------------------ Buffer management -------------------------- //

size_t get_free_buffer(bool *buffer_table) {
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        if (buffer_table[i] == false) {
            buffer_table[i] = true;
            return i;
        }
    }
    return SIZE_MAX;
}

void set_free_buffer(const size_t buffer_index, bool *buffer_table) {
    if (buffer_index >= NUMBER_OF_BUFFERS_PER_CLIENT) {
        return;
    }
    buffer_table[buffer_index] = false;
}

bool is_free_buffer(bool *buffer_table) {
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        if (buffer_table[i] == false) {
            return true;
        }
    }
    return false;
}

// ------------------------------ Buffer data management ------------------------------- //

buffer_copy_result_t copy_string_to_submission_buffer(const unsigned char *src, client_t *client_data) {
    buffer_copy_result_t result;
    size_t buffer_index = get_free_buffer(client_data->submission_buffer_table);
    if (buffer_index == SIZE_MAX) {
        result.rc = FS_ERROR_NO_FREE_SUBMISSION_BUFFERS;
        result.buffer_index = SIZE_MAX;
        return result;
    }
    microkit_debug_puts(OUTPUT_VERBOSITY, "CLIENT: copying string to submission buffer at index ");
    microkit_debug_put32(OUTPUT_VERBOSITY, buffer_index);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    unsigned char *dest = (unsigned char *)&client_data->submission_buffers[buffer_index];
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
    microkit_debug_puts(OUTPUT_VERBOSITY, "CLIENT: copied string: ");
    microkit_debug_puts(OUTPUT_VERBOSITY, (const char *)&client_data->submission_buffers[buffer_index]);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    result.buffer_index = buffer_index;
    return result;
}


buffer_copy_result_t copy_data_to_submission_buffer(const uint8_t *src, const size_t length, client_t *client_data) {
    buffer_copy_result_t result;
    size_t buffer_index = get_free_buffer(client_data->submission_buffer_table);
    if (buffer_index == SIZE_MAX) {
        result.rc = FS_ERROR_NO_FREE_SUBMISSION_BUFFERS;
        result.buffer_index = SIZE_MAX;
        return result;
    }
    uint8_t *dest = (uint8_t *)&client_data->submission_buffers[buffer_index];
    for (size_t i = 0; i < (length < CLIENT_BUFFER_SIZE ? length : CLIENT_BUFFER_SIZE); i++) {
        dest[i] = src[i];
    }
    result.rc = FS_OK;
    result.buffer_index = buffer_index;
    return result;
}