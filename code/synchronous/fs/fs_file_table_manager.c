#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../debug_output.h"

#include "include/fs_shared.h"
#include "include/fs_internal.h"
#include "include/fs_state.h"
#include "include/fs_utils.h"

file_descriptor_result_t get_file_descriptor(const uint8_t client_id, const size_t file_id) {
    if (file_id >= MAX_OPEN_FILES_PER_CLIENT) {
        return (file_descriptor_result_t){NULL, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND};
    }
    file_descriptor_t *fd = &file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + file_id];
    if (fd->i_node_index == -1) {
        return (file_descriptor_result_t){NULL, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND};
    }
    return (file_descriptor_result_t){fd, FS_OK};
}


bool is_i_node_open(const uint32_t i_node_index) {
    for (size_t client_id = 0; client_id < NUMBER_OF_CLIENTS; client_id++) {
        for (size_t file_id = 0; file_id < MAX_OPEN_FILES_PER_CLIENT; file_id++) {
            if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + file_id].i_node_index == i_node_index) {
                return true;
            }
        }
    }
    return false;
}


file_id_and_cursor_result_t add_i_node_to_fd_table(const uint8_t client_id, const uint32_t i_node_index,
                                                     const file_open_operations_t requested_operations) {
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index == i_node_index) {
            if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operations != requested_operations) {
                if (!valid_permissions(&i_node_table[i_node_index], client_id, requested_operations)) {
                    return (file_id_and_cursor_result_t){-1, -1, FS_ERR_PERMISSION};
                }
                file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operations = requested_operations;
            }
            return (file_id_and_cursor_result_t){i, file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].cursor_position, FS_OK};
        }
    }
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index == -1) {
            if (!valid_permissions(&i_node_table[i_node_index], client_id, requested_operations)) {
                return (file_id_and_cursor_result_t){-1, -1, FS_ERR_PERMISSION};
            }
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operations = requested_operations;
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index = i_node_index;
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].cursor_position = 0;
            return (file_id_and_cursor_result_t){i, 0, FS_OK};
        }
    }
    return (file_id_and_cursor_result_t){-1, -1, FS_ERR_MAX_OPEN_FILES_REACHED};
}


fs_result_t close_file_by_i_node_index(const uint8_t client_id, const uint32_t i_node_index) {
    microkit_debug_puts(OUTPUT_VERBOSITY, "closing i node ");
    microkit_debug_put32(OUTPUT_VERBOSITY, i_node_index);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n");
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        file_descriptor_t *fd = &file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i];
        if (fd->i_node_index == i_node_index) {
            fd->i_node_index = -1;
            fd->cursor_position = 0;
            fd->valid_operations = 0;
            return FS_OK;
        }
    }
    return FS_ERR_FILE_DESCRIPTOR_NOT_FOUND;
}