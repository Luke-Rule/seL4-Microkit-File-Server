#include <microkit.h>
#include <stdint.h>
#include <stddef.h>

#include "../debug_output.h"

#include "include/fs_api.h"


void copy_data_from_buffer(const uint8_t *src, uint8_t *dest, size_t length) {
    for (size_t i = 0; i < length; i++) {
        dest[i] = src[i];
    }
}

size_t copy_string_from_buffer(const unsigned char *src, unsigned char *dest, size_t max_length) {
    size_t i;
    for (i = 0; i < max_length - 1; i++) {
        dest[i] = src[i];
        if (dest[i] == '\0') {
            return i;
        }
    }
    // truncate if it exceeds max_length
    dest[max_length - 1] = '\0';
    return max_length - 1;
}

// ------------------------ Debug functions -------------------------- //

void mark_client_as_finished_running(uint8_t *buffer) {
    buffer[CLIENT_BUFFER_SIZE - 1] = 1;
    microkit_debug_puts(OUTPUT_VERBOSITY, "CLIENT: marked as finished running.\n");
}

fs_result_fileid_t send_create_file_request(const unsigned char *file_name, const permissions_t permissions, file_open_operations_t operations,  uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    copy_string_from_buffer(file_name, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);

    microkit_mr_set(0, OP_CREATE_FILE);
    microkit_mr_set(1, permissions);
    microkit_mr_set(2, operations);

    microkit_ppcall(channel_id, msg);

    fs_result_fileid_t res;
    res.rc = microkit_mr_get(0);
    res.file_id = *((uint32_t *)fs_buffer_base);
    return res;
}


fs_result_t send_create_directory_request(const unsigned char *dir_name, const permissions_t permissions, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    copy_string_from_buffer(dir_name, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);

    microkit_mr_set(0, OP_CREATE_DIRECTORY);
    microkit_mr_set(1, permissions);

    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);

    return return_code;
}


fs_result_fileid_t send_open_file_request(const file_open_operations_t ops, const unsigned char *file_name, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    copy_string_from_buffer(file_name, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);

    microkit_mr_set(0, OP_OPEN);
    microkit_mr_set(1, ops);

    microkit_ppcall(channel_id, msg);

    
    fs_result_fileid_t res;
    res.rc = microkit_mr_get(0);
    res.file_id = *((uint32_t *)fs_buffer_base);
    return res;
}


fs_result_t send_close_file_request(const uint32_t file_id, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_CLOSE);
    microkit_mr_set(1, file_id);

    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    return return_code;
}

fs_result_read_t send_read_file_request(const uint32_t file_id, const uint32_t length, uint8_t *fs_buffer_base, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    microkit_mr_set(0, OP_READ);
    microkit_mr_set(1, file_id);
    microkit_mr_set(2, length > CLIENT_BUFFER_SIZE ? CLIENT_BUFFER_SIZE : length);

    microkit_ppcall(channel_id, msg);

    fs_result_read_t res;
    res.rc =  microkit_mr_get(0);
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

    microkit_ppcall(channel_id, msg);

    fs_result_write_t res;
    res.rc = microkit_mr_get(0);
    res.bytes_written = ((uint32_t *)fs_buffer_base)[0];
    res.new_cursor_position = ((uint32_t *)(fs_buffer_base))[1];
    return res;
}


fs_result_t send_seek_file_request(const uint32_t file_id, const uint32_t position, int channel_id) {
    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    microkit_mr_set(0, OP_SEEK);
    microkit_mr_set(1, file_id);
    microkit_mr_set(2, position);

    microkit_ppcall(channel_id, msg);
    
    const int return_code = microkit_mr_get(0);
    return return_code;
}


fs_result_t send_delete_entry_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 1);
    microkit_mr_set(0, OP_DELETE);

    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    return return_code;
}

fs_result_t send_set_entry_permissions_request(const unsigned char *path, const permissions_t permissions, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 2);

    microkit_mr_set(0, OP_SET_PERMISSIONS);
    microkit_mr_set(1, permissions);

    microkit_ppcall(channel_id, msg);

    const int return_code = microkit_mr_get(0);
    return return_code;
}

fs_result_permissions_t send_get_entry_permissions_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    microkit_mr_set(0, OP_GET_PERMISSIONS);
    microkit_ppcall(channel_id, msg);

    fs_result_permissions_t res;
    res.rc = microkit_mr_get(0);
    res.permissions = (uint8_t)fs_buffer_base[0];

    return res;
}

fs_result_size_t send_get_entry_size_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    microkit_mr_set(0, OP_GET_SIZE);
    microkit_ppcall(channel_id, msg);

    fs_result_size_t res;
    res.rc = microkit_mr_get(0);

    res.size = *((uint32_t *)fs_buffer_base);

    return res;
}

fs_result_exists_t send_entry_exists_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 1);
    microkit_mr_set(0, OP_EXISTS);

    microkit_ppcall(channel_id, msg);
    fs_result_exists_t res;
    res.rc = microkit_mr_get(0);

    res.exists = fs_buffer_base[0];

    return res;
}

fs_result_list_t send_list_entries_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id) {
    copy_string_from_buffer(path, (unsigned char *)fs_buffer_base, CLIENT_BUFFER_SIZE);
    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    microkit_mr_set(0, OP_LIST);

    microkit_ppcall(channel_id, msg);

    fs_result_list_t res;
    res.rc = microkit_mr_get(0);
    res.data_address = fs_buffer_base;

    return res;
}