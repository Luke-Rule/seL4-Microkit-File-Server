#pragma once

#include <stdint.h>
#include <stddef.h>

#include "fs_shared.h"
#include "fs_shared_types.h"

#define FILE_SERVER_CHANNEL_ID 0

void mark_client_as_finished_running(uint8_t *buffer);

fs_result_fileid_t send_create_file_request(const unsigned char *file_name, const permissions_t permissions,
									const file_open_operations_t operations, unsigned char *fs_buffer_base, const uint8_t channel_id);
fs_result_t send_create_directory_request(const unsigned char *dir_name, const permissions_t permissions,
									 unsigned char *fs_buffer_base, const uint8_t channel_id);
fs_result_fileid_t send_open_file_request(const file_open_operations_t ops, const unsigned char *file_name,
							       unsigned char *fs_buffer_base, const uint8_t channel_id);
fs_result_t send_close_file_request(const uint32_t file_id, const uint8_t channel_id);
fs_result_read_t send_read_file_request(const uint32_t file_id, const size_t length, uint8_t *fs_buffer_base, const uint8_t channel_id);
fs_result_write_t send_write_file_request(const uint32_t file_id, const size_t length, const uint8_t *data,
							        uint8_t *fs_buffer_base, const uint8_t channel_id);
fs_result_t send_seek_file_request(const uint32_t file_id, const size_t position, const uint8_t channel_id);
fs_result_t send_delete_entry_request(const unsigned char *path, unsigned char *fs_buffer_base, const uint8_t channel_id);
fs_result_t send_set_entry_permissions_request(const unsigned char *path, const permissions_t permissions,
									  unsigned char *fs_buffer_base, const uint8_t channel_id);
fs_result_permissions_t send_get_entry_permissions_request(const unsigned char *path, unsigned char *fs_buffer_base, const uint8_t channel_id);
fs_result_size_t send_get_entry_size_request(const unsigned char *path, unsigned char *fs_buffer_base, const uint8_t channel_id);
fs_result_exists_t send_entry_exists_request(const unsigned char *path, unsigned char *fs_buffer_base, const uint8_t channel_id);
fs_result_list_t send_list_entries_request(const unsigned char *path, unsigned char *fs_buffer_base, const uint8_t channel_id);
