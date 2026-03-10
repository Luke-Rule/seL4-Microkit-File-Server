#include <microkit.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../debug_output.h"

#include "include/test_utils.h"

extern int tests_passed;
extern int tests_failed;

#define MAX_TEST_WAIT 2000

static void clear_client_buffer(uint8_t *fs_buffer_base) {
	for (size_t i = 0; i < CLIENT_BUFFER_SIZE; i++) {
		fs_buffer_base[i] = 0;
	}
}

void test_suite_begin(char *msg, uint8_t *fs_buffer_base) {
	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_YELLOW);
	microkit_debug_puts(TEST_VERBOSITY, "\n===== ");
	microkit_debug_puts(TEST_VERBOSITY, msg);
	microkit_debug_puts(TEST_VERBOSITY, " =====\n");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
	clear_client_buffer(fs_buffer_base);
}

void test_begin(char *msg) {
	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_YELLOW);
	microkit_debug_puts(TEST_VERBOSITY, "\nTest: ");
	microkit_debug_puts(TEST_VERBOSITY, msg);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
}

static bool fs_test_seek0(uint32_t fd, uint8_t channel_id) {
	return expect_eq_int(send_seek_file_request(fd, 0, channel_id), FS_OK, "Seek returned OK");
}

bool delete_entry_allow_missing(const unsigned char *path, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id) {
	int rc = send_delete_entry_request(path, fs_buffer_base, channel_id);
	if (rc == FS_OK || rc == FS_ERR_NOT_FOUND || rc == FS_ERR_FILE_DESCRIPTOR_NOT_FOUND) {
		return true;
	}
	return expect_eq_int(rc, FS_OK, step_name);
}

bool ensure_clean_test_root(uint8_t *fs_buffer_base, uint8_t channel_id) {
	if (!delete_entry_allow_missing((const unsigned char *)"/__tests", "Delete /__tests (cleanup)", fs_buffer_base, channel_id)) {
		return false;
	}

	return expect_eq_int(
		send_create_directory_request((const unsigned char *)"/__tests", PERM_PUBLIC, fs_buffer_base, channel_id),
		FS_OK,
		"Create /__tests returned OK");
}

bool fs_test_await_exists(const unsigned char *path, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id) {
	for (uint32_t i = 0; i < MAX_TEST_WAIT; i++) {
		fs_result_exists_t exists = send_entry_exists_request(path, fs_buffer_base, channel_id);
		if (!expect_eq_int(exists.rc, FS_OK, step_name)) {
			return false;
		}
		if (exists.exists == 1) {
			return true;
		}
		seL4_Yield();
	}

	return expect_true(false, "Timed out waiting for marker to exist");
}

bool fs_test_create_marker(const unsigned char *path, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id) {
	fs_result_fileid_t create_result = send_create_file_request(path, PERM_PUBLIC, READ_OP, fs_buffer_base, channel_id);
	if (!expect_eq_int(create_result.rc, FS_OK, step_name)) {
		return false;
	}

	return expect_eq_int(send_close_file_request(create_result.file_id, channel_id), FS_OK, "Close marker returned OK");
}

bool fs_test_open_expect_rc(file_open_operations_t ops, const unsigned char *path, uint32_t expected_rc, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id) {
	fs_result_fileid_t open_result = send_open_file_request(ops, path, fs_buffer_base, channel_id);
	if (!expect_eq_int(open_result.rc, (int)expected_rc, step_name)) {
		return false;
	}

	if (expected_rc == FS_OK) {
		return expect_eq_int(send_close_file_request(open_result.file_id, channel_id), FS_OK, "Close returned OK");
	}

	return true;
}

bool fs_test_open_read_expect(const unsigned char *path, const unsigned char *expected, size_t expected_len, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id) {
	fs_result_fileid_t open_result = send_open_file_request(READ_OP, path, fs_buffer_base, channel_id);
	if (!expect_eq_int(open_result.rc, FS_OK, step_name)) {
		return false;
	}

	if (!fs_test_seek0(open_result.file_id, channel_id)) {
		return false;
	}

	fs_result_read_t read_result = send_read_file_request(open_result.file_id, expected_len, fs_buffer_base, channel_id);
	if (!expect_eq_int(read_result.rc, FS_OK, "Read returned OK")) {
		return false;
	}
	if (!expect_equal_to_buffer(read_result.data_address, expected, expected_len, "Read matches expected")) {
		return false;
	}

	return expect_eq_int(send_close_file_request(open_result.file_id, channel_id), FS_OK, "Close returned OK");
}

bool fs_test_open_write_close(const unsigned char *path, const unsigned char *payload, size_t payload_len, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id) {
	fs_result_fileid_t open_result = send_open_file_request(READ_WRITE_OP, path, fs_buffer_base, channel_id);
	if (!expect_eq_int(open_result.rc, FS_OK, step_name)) {
		return false;
	}

	if (!fs_test_seek0(open_result.file_id, channel_id)) {
		return false;
	}

	fs_result_write_t write_result = send_write_file_request(open_result.file_id, payload_len, payload, fs_buffer_base, channel_id);
	if (!expect_eq_int(write_result.rc, FS_OK, "Write returned OK")) {
		return false;
	}

	return expect_eq_int(send_close_file_request(open_result.file_id, channel_id), FS_OK, "Close returned OK");
}

bool fs_test_create_and_write_file(const unsigned char *path, permissions_t perms, file_open_operations_t create_ops, const unsigned char *payload, size_t payload_len, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id) {
	fs_result_fileid_t create_result = send_create_file_request(path, perms, create_ops, fs_buffer_base, channel_id);
	if (!expect_eq_int(create_result.rc, FS_OK, step_name)) {
		return false;
	}

	if (!fs_test_seek0(create_result.file_id, channel_id)) {
		return false;
	}

	fs_result_write_t write_result = send_write_file_request(create_result.file_id, payload_len, payload, fs_buffer_base, channel_id);
	if (!expect_eq_int(write_result.rc, FS_OK, "Write returned OK")) {
		return false;
	}

	return expect_eq_int(send_close_file_request(create_result.file_id, channel_id), FS_OK, "Close returned OK");
}

bool fs_test_create_file_expect_rc(const unsigned char *path, permissions_t perms, file_open_operations_t create_ops, uint32_t expected_rc, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id) {
	fs_result_fileid_t create_result = send_create_file_request(path, perms, create_ops, fs_buffer_base, channel_id);
	if (!expect_eq_int(create_result.rc, (int)expected_rc, step_name)) {
		return false;
	}

	if (expected_rc == FS_OK) {
		return expect_eq_int(send_close_file_request(create_result.file_id, channel_id), FS_OK, "Close returned OK");
	}

	return true;
}

bool fs_test_delete_expect_rc(const unsigned char *path, uint32_t expected_rc, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id) {
	return expect_eq_int(send_delete_entry_request(path, fs_buffer_base, channel_id), (int)expected_rc, step_name);
}

bool fs_test_set_perm_expect_rc(const unsigned char *path, permissions_t perms, uint32_t expected_rc, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id) {
	return expect_eq_int(send_set_entry_permissions_request(path, perms, fs_buffer_base, channel_id), (int)expected_rc, step_name);
}

void run_test_suite(const char *name, test_fn_t test, uint8_t *fs_buffer_base) {
	test_suite_begin((char *)name, fs_buffer_base);

	if (test()) {
		tests_passed++;
		microkit_debug_putc(TEST_VERBOSITY, '\n');
		output_suite_pass((unsigned char *)name);
		return;
	}

	tests_failed++;
	output_fail((unsigned char *)name);
}
