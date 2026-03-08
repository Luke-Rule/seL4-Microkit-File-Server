#pragma once

#include <stdint.h>
#include <stddef.h>

#include "fs_shared.h"

#define FILE_SERVER_CHANNEL_ID 0

void mark_client_as_finished_running(uint8_t *buffer);

fs_result_fileid_t send_create_file_request(const unsigned char *file_name, permissions_t permissions,
									file_open_operations_t operations, uint8_t *fs_buffer_base, int channel_id);
fs_result_t send_create_directory_request(const unsigned char *dir_name, permissions_t permissions,
										 uint8_t *fs_buffer_base, int channel_id);
fs_result_fileid_t send_open_file_request(file_open_operations_t ops, const unsigned char *file_name,
								       uint8_t *fs_buffer_base, int channel_id);
fs_result_t send_close_file_request(uint32_t file_id, int channel_id);
fs_result_read_t send_read_file_request(uint32_t file_id, uint32_t length, uint8_t *fs_buffer_base, int channel_id);
fs_result_write_t send_write_file_request(uint32_t file_id, size_t length, const uint8_t *data,
								        uint8_t *fs_buffer_base, int channel_id);
fs_result_t send_seek_file_request(uint32_t file_id, uint32_t position, int channel_id);
fs_result_t send_delete_entry_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id);
fs_result_t send_set_entry_permissions_request(const unsigned char *path, permissions_t permissions,
											  uint8_t *fs_buffer_base, int channel_id);
fs_result_permissions_t send_get_entry_permissions_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id);
fs_result_size_t send_get_entry_size_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id);
fs_result_exists_t send_entry_exists_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id);
fs_result_list_t send_list_entries_request(const unsigned char *path, uint8_t *fs_buffer_base, int channel_id);
