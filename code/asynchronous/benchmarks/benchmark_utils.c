#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../debug_output.h"

#include "benchmark_utils.h"
#include "../fs/include/fs_api.h"

static size_t append_c_string(unsigned char *dest, size_t offset, size_t capacity,
							  const char *src)
{
	size_t index = offset;

	while (*src != '\0' && index + 1 < capacity) {
		dest[index++] = (unsigned char)*src++;
	}

	if (index < capacity) {
		dest[index] = '\0';
	}

	return index;
}

static size_t append_u32(unsigned char *dest, size_t offset, size_t capacity,
						 uint32_t value)
{
	char digits[10];
	size_t count = 0;
	size_t index = offset;

	if (value == 0) {
		if (index + 1 < capacity) {
			dest[index++] = '0';
			dest[index] = '\0';
		}
		return index;
	}

	while (value > 0 && count < sizeof(digits)) {
		digits[count++] = (char)('0' + (value % 10u));
		value /= 10u;
	}

	while (count > 0 && index + 1 < capacity) {
		dest[index++] = (unsigned char)digits[--count];
	}

	if (index < capacity) {
		dest[index] = '\0';
	}

	return index;
}

static void make_file_path(unsigned char *dest, size_t capacity,
						   const unsigned char *root_path, uint32_t iteration)
{
	size_t index = 0;
	const unsigned char *src = root_path;

	while (*src != '\0' && index + 1 < capacity) {
		dest[index++] = *src++;
	}

	if (index + 1 < capacity) {
		dest[index++] = '/';
		dest[index] = '\0';
	}

	index = append_c_string(dest, index, capacity, "file_");
	index = append_u32(dest, index, capacity, iteration);
	append_c_string(dest, index, capacity, ".bin");
}

static void copy_path(unsigned char *dest, size_t capacity,
					  const unsigned char *src)
{
	size_t index = 0;

	while (*src != '\0' && index + 1 < capacity) {
		dest[index++] = *src++;
	}

	if (index < capacity) {
		dest[index] = '\0';
	}
}

static void fill_pattern(uint8_t *buffer, size_t length, uint32_t seed)
{
	for (size_t i = 0; i < length; i++) {
		buffer[i] = (uint8_t)((seed + i) & 0xffu);
	}
}

static bool buffers_equal(const uint8_t *lhs, const uint8_t *rhs, const size_t length)
{
	for (size_t i = 0; i < length; i++) {
		if (lhs[i] != rhs[i]) {
			return false;
		}
	}

	return true;
}

static void clear_client_state(client_t *client_data)
{
	client_data->submission_queue_head = 0;
	client_data->submission_queue_tail = 0;
	client_data->completion_queue_head = 0;
	client_data->completion_queue_tail = 0;
	client_data->flags.ready_flag = 0;
	client_data->flags.complete_flag = 0;
	client_data->flags.finished_running_flag = 0;

	for (size_t i = 0; i < MAX_QUEUE_ENTRIES; i++) {
		client_data->submission_queue[i].operation_code = 0;
		client_data->submission_queue[i].parameter1 = 0;
		client_data->submission_queue[i].parameter2 = 0;
		client_data->submission_queue[i].buffer_index = 0;
		client_data->completion_queue[i].return_code = 0;
		client_data->completion_queue[i].parameter1 = 0;
		client_data->completion_queue[i].parameter2 = 0;
		client_data->completion_queue[i].buffer_index = 0;
	}

	for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
		client_data->submission_buffer_table[i] = false;
		client_data->completion_buffer_table[i] = false;
		for (size_t j = 0; j < CLIENT_BUFFER_SIZE; j++) {
			client_data->submission_buffers[i].data[j] = 0;
			client_data->completion_buffers[i].data[j] = 0;
		}
	}
}

static bool expect_queue_rc(const fs_result_t rc, const char *operation)
{
	if (rc == FS_OK) {
		return true;
	}

	microkit_debug_puts(TEST_VERBOSITY, operation);
	microkit_debug_puts(TEST_VERBOSITY, " queue failed with rc=");
	microkit_debug_put32(TEST_VERBOSITY, (uint32_t)rc);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
	return false;
}

static bool expect_completion_rc(const uint8_t rc, const char *operation)
{
	if (rc == FS_OK) {
		return true;
	}

	microkit_debug_puts(TEST_VERBOSITY, operation);
	microkit_debug_puts(TEST_VERBOSITY, " completion failed with rc=");
	microkit_debug_put32(TEST_VERBOSITY, rc);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
	return false;
}

static bool get_completion_or_fail(client_t *client_data,
							   completion_queue_entry_t *completion,
							   const char *operation)
{
	fs_result_t rc = get_next_completion_entry(client_data, completion);
	if (rc == FS_OK) {
		return true;
	}

	microkit_debug_puts(TEST_VERBOSITY, operation);
	microkit_debug_puts(TEST_VERBOSITY, " had no completion rc=");
	microkit_debug_put32(TEST_VERBOSITY, (uint32_t)rc);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
	return false;
}

static bool queue_create_file(client_t *client_data, const unsigned char *path)
{
	return expect_queue_rc(
		send_create_file_request(path, PERM_PUBLIC, READ_WRITE_OP, client_data),
		"create benchmark file");
}

static bool queue_write_seek_read_close_delete(client_t *client_data,
									   const uint32_t file_id,
									   const uint8_t *write_buffer,
									   const unsigned char *path)
{
	if (!expect_queue_rc(
			send_write_file_request(file_id, BENCHMARK_FILE_SIZE, write_buffer,
									client_data),
			"write benchmark file")) {
		return false;
	}

	if (!expect_queue_rc(send_seek_file_request(file_id, 0, client_data),
						 "seek benchmark file")) {
		return false;
	}

	if (!expect_queue_rc(
			send_read_file_request(file_id, BENCHMARK_FILE_SIZE, client_data),
			"read benchmark file")) {
		return false;
	}

	if (!expect_queue_rc(send_close_file_request(file_id, client_data),
						 "close benchmark file")) {
		return false;
	}

	return expect_queue_rc(send_delete_entry_request(path, client_data),
						   "delete benchmark file");
}

static bool drain_create_completion(client_t *client_data, const char *operation,
								    uint32_t *file_id)
{
	completion_queue_entry_t completion;

	if (!get_completion_or_fail(client_data, &completion, operation)) {
		return false;
	}

	if (!expect_completion_rc(completion.return_code, operation)) {
		return false;
	}

	*file_id = completion.parameter1;
	return true;
}

static bool drain_file_batch(client_t *client_data, const uint8_t *expected_data,
							 const bool has_next_create, uint32_t *next_file_id)
{
	completion_queue_entry_t completion;

	if (!get_completion_or_fail(client_data, &completion, "write benchmark file") ||
		!expect_completion_rc(completion.return_code, "write benchmark file")) {
		return false;
	}

	if (completion.parameter1 != BENCHMARK_FILE_SIZE) {
		microkit_debug_puts(TEST_VERBOSITY, "write size mismatch\n");
		return false;
	}

	if (!get_completion_or_fail(client_data, &completion, "seek benchmark file") ||
		!expect_completion_rc(completion.return_code, "seek benchmark file")) {
		return false;
	}

	if (!get_completion_or_fail(client_data, &completion, "read benchmark file") ||
		!expect_completion_rc(completion.return_code, "read benchmark file")) {
		return false;
	}

	if (completion.parameter1 != BENCHMARK_FILE_SIZE) {
		microkit_debug_puts(TEST_VERBOSITY, "read size mismatch\n");
		return false;
	}

	if (!buffers_equal(
			client_data->completion_buffers[completion.buffer_index].data,
			expected_data, BENCHMARK_FILE_SIZE)) {
		microkit_debug_puts(TEST_VERBOSITY, "readback mismatch\n");
		set_free_completion_buffer(client_data, completion.buffer_index);
		return false;
	}

	set_free_completion_buffer(client_data, completion.buffer_index);

	if (!get_completion_or_fail(client_data, &completion, "close benchmark file") ||
		!expect_completion_rc(completion.return_code, "close benchmark file")) {
		return false;
	}

	if (!get_completion_or_fail(client_data, &completion, "delete benchmark file") ||
		!expect_completion_rc(completion.return_code, "delete benchmark file")) {
		return false;
	}

	if (!has_next_create) {
		return true;
	}

	return drain_create_completion(client_data, "create benchmark file",
								   next_file_id);
}

bool benchmark_run_workload(client_t *client_data, const unsigned char *root_path,
						   uint32_t seed_base)
{
	unsigned char current_path[96];
	unsigned char next_path[96];
	uint8_t write_buffer[BENCHMARK_FILE_SIZE];
	completion_queue_entry_t completion;
	uint32_t current_file_id;
	uint32_t next_file_id = 0;

	clear_client_state(client_data);

	if (!expect_queue_rc(send_delete_entry_request(root_path, client_data),
						 "delete benchmark root")) {
		return false;
	}

	if (!expect_queue_rc(
			send_create_directory_request(root_path, PERM_PUBLIC, client_data),
			"create benchmark root")) {
		return false;
	}

	notify_file_server_and_wait_for_all_operations(client_data, 2);

	if (!get_completion_or_fail(client_data, &completion, "delete benchmark root")) {
		return false;
	}

	if (completion.return_code != FS_OK && completion.return_code != FS_ERR_NOT_FOUND &&
		completion.return_code != FS_ERR_FILE_DESCRIPTOR_NOT_FOUND) {
		return expect_completion_rc(completion.return_code, "delete benchmark root");
	}

	if (!get_completion_or_fail(client_data, &completion, "create benchmark root") ||
		!expect_completion_rc(completion.return_code, "create benchmark root")) {
		return false;
	}

	make_file_path(current_path, sizeof(current_path), root_path, 0);
	if (!queue_create_file(client_data, current_path)) {
		return false;
	}

	notify_file_server_and_wait_for_all_operations(client_data, 1);
	if (!drain_create_completion(client_data, "create benchmark file",
								 &current_file_id)) {
		return false;
	}

	for (uint32_t iteration = 0; iteration < BENCHMARK_FILE_COUNT; iteration++) {
		int has_next_create = iteration + 1 < BENCHMARK_FILE_COUNT;

		fill_pattern(write_buffer, sizeof(write_buffer), seed_base + iteration * 17u);

		if (!queue_write_seek_read_close_delete(client_data, current_file_id,
										   write_buffer, current_path)) {
			return false;
		}

		if (has_next_create) {
			make_file_path(next_path, sizeof(next_path), root_path, iteration + 1);
			if (!queue_create_file(client_data, next_path)) {
				return false;
			}
		}

		notify_file_server_and_wait_for_all_operations(
			client_data,
			(uint8_t)(has_next_create ? 6 : 5));

		if (!drain_file_batch(client_data, write_buffer, has_next_create,
							  &next_file_id)) {
			return false;
		}

		if (has_next_create) {
			current_file_id = next_file_id;
			copy_path(current_path, sizeof(current_path), next_path);
		}
	}

	return true;
}

void benchmark_finish(client_t *client_data, bool success)
{
	if (!success) {
		microkit_debug_puts(TEST_VERBOSITY, "benchmark client failed\n");
	}

	mark_client_as_finished_running(client_data);
	microkit_notify(FILE_SERVER_CHANNEL_ID);
	seL4_Yield();
}
