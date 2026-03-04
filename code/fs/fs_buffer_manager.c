#include <microkit.h>
#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_buffer_manager.h"
#include "fs_shared.h"

// ------------------------ Buffer management -------------------------- //

int get_free_buffer(uint8_t *buffer_table) {
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        if (buffer_table[i] == 0) {
            buffer_table[i] = 1;
            return i;
        }
    }
    return -1;
}

void set_free_buffer(int buffer_index, uint8_t *buffer_table) {
    if (buffer_index < 0 || buffer_index >= NUMBER_OF_BUFFERS_PER_CLIENT) {
        return;
    }
    buffer_table[buffer_index] = 0;
}

// ------------------------------ Buffer data management ------------------------------- //

buffer_copy_result_t copy_string_to_submission_buffer(const unsigned char *src, client_t *client_data) {
    buffer_copy_result_t result;
    int buffer_index = get_free_buffer(client_data->submission_buffer_table);
    if (buffer_index == -1) {
        result.rc = FS_ERROR_NO_FREE_SUBMISSION_BUFFERS;
        result.buffer_index = -1;
        return result;
    }
    microkit_debug_puts("CLIENT: copying string to submission buffer at index ");
    microkit_debug_put32(buffer_index);
    microkit_debug_puts("\n");
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
    microkit_debug_puts("CLIENT: copied string: ");
    microkit_debug_puts((const char *)&client_data->submission_buffers[buffer_index]);
    microkit_debug_puts("\n");
    result.buffer_index = buffer_index;
    return result;
}


buffer_copy_result_t copy_data_to_submission_buffer(const uint8_t *src, const size_t length, client_t *client_data) {
    buffer_copy_result_t result;
    int buffer_index = get_free_buffer(client_data->submission_buffer_table);
    if (buffer_index == -1) {
        result.rc = FS_ERROR_NO_FREE_SUBMISSION_BUFFERS;
        result.buffer_index = -1;
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