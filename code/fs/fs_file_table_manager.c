#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_buffer_manager.h"
#include "fs_shared.h"
#include "fs_internal.h"

#include "fs_state.h"
#include "fs_utils.h"

file_descriptor_result_t get_file_descriptor(const uint32_t client_id, const uint32_t file_index) {
    if (file_index >= MAX_OPEN_FILES_PER_CLIENT) {
        return (file_descriptor_result_t){NULL, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND};
    }
    file_descriptor_t *fd = &file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + file_index];
    if (fd->i_node_index == -1) {
        return (file_descriptor_result_t){NULL, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND};
    }
    return (file_descriptor_result_t){fd, FS_OK};
}

file_index_and_cursor_result_t add_i_node_to_fd_table(const uint32_t client_id, const uint32_t i_node_index,
                                                     const uint8_t requested_operations) {
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index == i_node_index) {
            if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operations != requested_operations) {
                if (!valid_permissions(&i_node_table[i_node_index], client_id, requested_operations)) {
                    return (file_index_and_cursor_result_t){-1, -1, FS_ERR_PERMISSION};
                }
                file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operations = requested_operations;
            }
            return (file_index_and_cursor_result_t){i, file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].cursor_position, FS_OK};
        }
    }
    for (size_t i = 0; i < MAX_OPEN_FILES_PER_CLIENT; i++) {
        if (file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index == -1) {
            if (!valid_permissions(&i_node_table[i_node_index], client_id, requested_operations)) {
                return (file_index_and_cursor_result_t){-1, -1, FS_ERR_PERMISSION};
            }
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].valid_operations = requested_operations;
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].i_node_index = i_node_index;
            file_descriptor_table[client_id * MAX_OPEN_FILES_PER_CLIENT + i].cursor_position = 0;
            return (file_index_and_cursor_result_t){i, 0, FS_OK};
        }
    }
    return (file_index_and_cursor_result_t){-1, -1, FS_ERR_MAX_OPEN_FILES_REACHED};
}


fs_result_t close_file_by_i_node_index(const uint32_t client_id, const uint32_t i_node_index) {
    microkit_dbg_puts("closing i node ");
    microkit_dbg_put32(i_node_index);
    microkit_dbg_puts("\n");
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