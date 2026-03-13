#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../debug_output.h"
#include "../../timing_helpers.h"

#include "fs_shared.h"
#include "benchmark_shared.h"
#include "benchmark_utils.h"
#include "../fs/include/fs_api.h"

static unsigned char benchmark_path[96];
static uint8_t benchmark_write_buffer[BENCHMARK_FILE_SIZE];
static uint8_t benchmark_expected_data[BENCHMARK_FILE_SIZE];

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

static bool queue_write_close(client_t *client_data, const uint32_t file_id,
				      const uint8_t *write_buffer)
{
	if (!expect_queue_rc(
			send_write_file_request(file_id, BENCHMARK_FILE_SIZE, write_buffer,
									client_data),
			"write benchmark file")) {
		return false;
	}

	return expect_queue_rc(send_close_file_request(file_id, client_data),
				   "close benchmark file");
}

static bool queue_open_file(client_t *client_data, const unsigned char *path)
{
	return expect_queue_rc(send_open_file_request(path, READ_OP, client_data),
				   "open benchmark file");
}

static bool queue_read_seek_read_delete(client_t *client_data,
					    const uint32_t file_id,
					    const unsigned char *path)
{
	if (!expect_queue_rc(
			send_read_file_request(file_id, BENCHMARK_FILE_SIZE, client_data),
			"read benchmark file")) {
		return false;
	}

	if (!expect_queue_rc(send_seek_file_request(file_id, 0, client_data),
					 "seek benchmark file")) {
		return false;
	}

	if (!expect_queue_rc(
			send_read_file_request(file_id, BENCHMARK_FILE_SIZE, client_data),
			"read benchmark file after seek")) {
		return false;
	}

	return expect_queue_rc(send_delete_entry_request(path, client_data),
				   "delete benchmark file");
}

static bool drain_file_id_completion(client_t *client_data, const char *operation,
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

static bool drain_read_completion(client_t *client_data,
				  completion_queue_entry_t *completion,
				  const uint8_t *expected_data,
				  const char *operation)
{
	if (!get_completion_or_fail(client_data, completion, operation) ||
		!expect_completion_rc(completion->return_code, operation)) {
		return false;
	}

	if (completion->parameter1 != BENCHMARK_FILE_SIZE) {
		microkit_debug_puts(TEST_VERBOSITY, "read size mismatch\n");
		return false;
	}

	if (!benchmark_buffers_equal(
			client_data->completion_buffers[completion->buffer_index].data,
			expected_data, BENCHMARK_FILE_SIZE)) {
		microkit_debug_puts(TEST_VERBOSITY, "readback mismatch\n");
		set_free_completion_buffer(client_data, completion->buffer_index);
		return false;
	}

	set_free_completion_buffer(client_data, completion->buffer_index);
	return true;
}

static bool drain_write_close_batch(client_t *client_data)
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

	if (!get_completion_or_fail(client_data, &completion, "close benchmark file") ||
		!expect_completion_rc(completion.return_code, "close benchmark file")) {
		return false;
	}

	return true;
}

static bool drain_open_batch(client_t *client_data, uint32_t *file_id)
{
	return drain_file_id_completion(client_data, "open benchmark file", file_id);
}

static bool drain_read_seek_read_delete_batch(client_t *client_data,
					      uint32_t iteration,
					      uint32_t seed_base)
{
	completion_queue_entry_t completion;

	benchmark_fill_pattern(benchmark_expected_data,
			       sizeof(benchmark_expected_data),
			       seed_base + iteration * 17u);

	if (!drain_read_completion(client_data, &completion, benchmark_expected_data,
				   "read benchmark file")) {
		return false;
	}

	if (!get_completion_or_fail(client_data, &completion, "seek benchmark file") ||
		!expect_completion_rc(completion.return_code, "seek benchmark file")) {
		return false;
	}

	if (!drain_read_completion(client_data, &completion, benchmark_expected_data,
				   "read benchmark file after seek")) {
		return false;
	}

	if (!get_completion_or_fail(client_data, &completion, "delete benchmark file") ||
		!expect_completion_rc(completion.return_code, "delete benchmark file")) {
		return false;
	}

	return true;
}

bool benchmark_prepare_root(client_t *client_data, const unsigned char *root_path)
{
	completion_queue_entry_t completion;

	benchmark_clear_client_state(client_data);

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

	return true;
}

bool benchmark_run_iterations(client_t *client_data, const unsigned char *root_path,
					  uint32_t seed_base)
{
	uint32_t created_file_id;
	uint32_t opened_file_id;

	for (uint32_t iteration = 0; iteration < BENCHMARK_FILE_COUNT; iteration++) {
		benchmark_make_file_path(benchmark_path, sizeof(benchmark_path), root_path,
					 iteration);

		if (!queue_create_file(client_data, benchmark_path)) {
			return false;
		}

		notify_file_server_and_wait_for_all_operations(client_data, 1);
		if (!drain_file_id_completion(client_data, "create benchmark file",
					     &created_file_id)) {
			return false;
		}

		benchmark_fill_pattern(benchmark_write_buffer,
				   sizeof(benchmark_write_buffer),
				   seed_base + iteration * 17u);
		if (!queue_write_close(client_data, created_file_id,
				       benchmark_write_buffer)) {
			return false;
		}

		notify_file_server_and_wait_for_all_operations(client_data, 2);
		if (!drain_write_close_batch(client_data)) {
			return false;
		}

		if (!queue_open_file(client_data, benchmark_path)) {
			return false;
		}

		notify_file_server_and_wait_for_all_operations(client_data, 1);
		if (!drain_open_batch(client_data, &opened_file_id)) {
			return false;
		}

		if (!queue_read_seek_read_delete(client_data, opened_file_id,
						 benchmark_path)) {
			return false;
		}

		notify_file_server_and_wait_for_all_operations(client_data, 4);
		if (!drain_read_seek_read_delete_batch(client_data, iteration, seed_base)) {
			return false;
		}
	}

	return true;
}

void benchmark_report_timing(const uint8_t label, uint64_t elapsed_ticks)
{
	uint64_t freq = read_cntfrq();
	uint64_t total_us = 0;
	uint64_t average_ticks = elapsed_ticks / BENCHMARK_FILE_COUNT;
	uint64_t average_us = 0;

	if (freq != 0) {
		total_us = (elapsed_ticks * 1000000u) / freq;
		average_us = total_us / BENCHMARK_FILE_COUNT;
	}

    // print from single point of high pri so no cutoff strings
	microkit_msginfo msginfo = microkit_msginfo_new(CLIENT_BENCHMARK_LABEL, 3);
	microkit_mr_set(0, label);
	microkit_mr_set(1, total_us);
	microkit_mr_set(2, average_us);
	microkit_ppcall(FILE_SERVER_CHANNEL_ID, msginfo);
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