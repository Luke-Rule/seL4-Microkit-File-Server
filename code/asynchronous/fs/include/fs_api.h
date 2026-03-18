#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "fs_shared.h"

#define FILE_SERVER_CHANNEL_ID 0
#define BLOCK_ON_NOTIFY true
#define DONT_BLOCK_ON_NOTIFY false

void mark_client_as_finished_running(client_t *client_data);
void debug_print_return_code(const char *operation, const uint8_t return_code);

void notify_file_server(client_t *client_data, const bool wait_for_completion);

bool get_if_any_operations_completed(client_t *client_data);
uint8_t get_number_of_completed_operations(client_t *client_data);
void wait_until_n_operations_completed(client_t *client_data, const size_t n);
void notify_file_server_and_wait_for_all_operations(client_t *client_data, const size_t number_of_operations);

void set_free_completion_buffer(client_t *client_data, const size_t buffer_index);
fs_result_t get_next_completion_entry(client_t *client_data, completion_queue_entry_t *out);

fs_result_t send_create_file_request(const unsigned char *file_name, const permissions_t permissions,
									const file_open_operations_t operations, client_t *client_data);
fs_result_t send_create_directory_request(const unsigned char *dir_name, const permissions_t permissions,
										 client_t *client_data);
fs_result_t send_open_file_request(const unsigned char *file_name, const file_open_operations_t ops, 
								  client_t *client_data);
fs_result_t send_close_file_request(const uint32_t file_id, client_t *client_data);
fs_result_t send_read_file_request(const uint32_t file_id, const size_t length, client_t *client_data);
fs_result_t send_write_file_request(const uint32_t file_id, const size_t length, const uint8_t *data,
								   client_t *client_data);
fs_result_t send_seek_file_request(const uint32_t file_id, const uint32_t position, client_t *client_data);
fs_result_t send_delete_entry_request(const unsigned char *path, client_t *client_data);
fs_result_t send_set_entry_permissions_request(const unsigned char *path, const permissions_t permissions,
											  client_t *client_data);
fs_result_t send_get_entry_permissions_request(const unsigned char *path, client_t *client_data);
fs_result_t send_get_entry_size_request(const unsigned char *path, client_t *client_data);
fs_result_t send_entry_exists_request(const unsigned char *path, client_t *client_data);
fs_result_t send_list_entries_request(const unsigned char *path, client_t *client_data);
