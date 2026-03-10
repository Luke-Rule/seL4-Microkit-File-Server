#include <microkit.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../../debug_output.h"

#include "../../fs/include/fs_api.h"
#include "../include/test_utils.h"

uintptr_t fs_data_base;
uint8_t *fs_buffer_base;
int tests_passed = 0;
int tests_failed = 0;

static bool test_list_empty_directory(void) {
	if (!ensure_clean_test_root(fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	fs_result_list_t list_result = send_list_entries_request((const unsigned char *)"/__tests", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(list_result.rc, FS_OK, "List empty directory returned OK")) {
		return false;
	}

	return expect_equal_to_buffer(list_result.data_address, (const uint8_t *)"\0", 1, "Empty directory lists nothing");
}

static bool test_create_write_read_roundtrip(void) {
	if (!ensure_clean_test_root(fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	const unsigned char path[] = "/__tests/a.txt";
	const unsigned char data[] = "Hello, seL4 File Server!";

	fs_result_fileid_t create_result = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(create_result.rc, FS_OK, "Create file returned OK")) {
		return false;
	}
	uint32_t fd = create_result.file_id;

	test_begin((char *)"Write zero bytes then read zero bytes (cursor should not move)");
	fs_result_write_t write_zero = send_write_file_request(fd, 0, (const uint8_t *)"x", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(write_zero.rc, FS_OK, "Write 0 bytes returned OK")) {
		return false;
	}
	if (!expect_eq_uint32(write_zero.bytes_written, 0, "Bytes written is 0")) {
		return false;
	}
	if (!expect_eq_uint32(write_zero.new_cursor_position, 0, "Cursor unchanged after write 0")) {
		return false;
	}

	fs_result_read_t read_zero = send_read_file_request(fd, 0, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(read_zero.rc, FS_OK, "Read 0 bytes returned OK")) {
		return false;
	}
	if (!expect_eq_uint32(read_zero.bytes_read, 0, "Bytes read is 0")) {
		return false;
	}
	if (!expect_eq_uint32(read_zero.new_cursor_position, 0, "Cursor unchanged after read 0")) {
		return false;
	}

	output_pass((unsigned char *)"Write zero bytes then read zero bytes (cursor should not move)");

	test_begin((char *)"Write then read back");
	fs_result_write_t write_result = send_write_file_request(fd, sizeof(data), data, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(write_result.rc, FS_OK, "Write returned OK")) {
		return false;
	}
	if (!expect_eq_uint32(write_result.bytes_written, sizeof(data), "Bytes written equals data length")) {
		return false;
	}

	if (!expect_eq_int(send_seek_file_request(fd, 0, FILE_SERVER_CHANNEL_ID), FS_OK, "Seek returned OK")) {
		return false;
	}

	fs_result_read_t read_result = send_read_file_request(fd, sizeof(data), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(read_result.rc, FS_OK, "Read returned OK")) {
		return false;
	}
	if (!expect_eq_uint32(read_result.bytes_read, sizeof(data), "Bytes read equals data length")) {
		return false;
	}
	if (!expect_equal_to_buffer(read_result.data_address, data, sizeof(data), "Readback matches write")) {
		return false;
	}

	if (!expect_eq_int(send_close_file_request(fd, FILE_SERVER_CHANNEL_ID), FS_OK, "Close returned OK")) {
		return false;
	}

	output_pass((unsigned char *)"Write then read back");
	return true;
}

static bool test_duplicate_create_fails(void) {
	if (!ensure_clean_test_root(fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	const unsigned char path[] = "/__tests/dup.txt";
	fs_result_fileid_t first = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(first.rc, FS_OK, "Create dup.txt returned OK")) {
		return false;
	}

	fs_result_fileid_t second = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	return expect_eq_int(second.rc, FS_ERR_ALREADY_EXISTS, "Duplicate create fails with already exists");
}

static bool test_directory_file_conflicts(void) {
	if (!ensure_clean_test_root(fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	test_begin((char *)"Create a directory and ensure you cannot open it as a file");
	if (!expect_eq_int(send_create_directory_request((const unsigned char *)"/__tests/subdir", PERM_PUBLIC, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_OK, "Create directory returned OK")) {
		return false;
	}
	if (!fs_test_open_expect_rc(READ_OP, (const unsigned char *)"/__tests/subdir", FS_ERR_INVALID_PATH, "Open dir as file", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Create a directory and ensure you cannot open it as a file");

	test_begin((char *)"Cannot create a file with same name as existing directory");
	fs_result_fileid_t create_dir_name = send_create_file_request((const unsigned char *)"/__tests/subdir", PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(create_dir_name.rc, FS_ERR_ALREADY_EXISTS, "File named like existing directory fails")) {
		return false;
	}
	output_pass((unsigned char *)"Cannot create a file with same name as existing directory");

	test_begin((char *)"Create a file and ensure you cannot create directory with same name");
	fs_result_fileid_t create_file = send_create_file_request((const unsigned char *)"/__tests/a.txt", PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(create_file.rc, FS_OK, "Create file returned OK")) {
		return false;
	}
	if (!expect_eq_int(send_create_directory_request((const unsigned char *)"/__tests/a.txt", PERM_PUBLIC, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_ERR_ALREADY_EXISTS, "Directory named like existing file fails")) {
		return false;
	}
	output_pass((unsigned char *)"Create a file and ensure you cannot create directory with same name");

	return true;
}

static bool test_nested_directory_listing_and_size(void) {
	if (!ensure_clean_test_root(fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	const unsigned char dir_path[] = "/__tests/subdir";
	const unsigned char file_path[] = "/__tests/subdir/nestedfile.txt";
	const unsigned char payload[] = "Nested file data.";

	if (!expect_eq_int(send_create_directory_request(dir_path, PERM_PUBLIC, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_OK, "Mkdir returned OK")) {
		return false;
	}

	fs_result_list_t empty_list = send_list_entries_request(dir_path, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(empty_list.rc, FS_OK, "List empty subdir returned OK")) {
		return false;
	}
	if (!expect_equal_to_buffer(empty_list.data_address, (const uint8_t *)"\0", 1, "Empty subdir lists nothing")) {
		return false;
	}

	fs_result_fileid_t create_result = send_create_file_request(file_path, PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(create_result.rc, FS_OK, "Create nested file returned OK")) {
		return false;
	}
	uint32_t fd = create_result.file_id;

	fs_result_write_t write_result = send_write_file_request(fd, sizeof(payload), payload, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(write_result.rc, FS_OK, "Write nested returned OK")) {
		return false;
	}

	if (!expect_eq_int(send_seek_file_request(fd, 0, FILE_SERVER_CHANNEL_ID), FS_OK, "Seek nested returned OK")) {
		return false;
	}

	fs_result_read_t read_result = send_read_file_request(fd, sizeof(payload), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(read_result.rc, FS_OK, "Read nested returned OK")) {
		return false;
	}
	if (!expect_equal_to_buffer(read_result.data_address, payload, sizeof(payload), "Nested readback matches write")) {
		return false;
	}

	fs_result_list_t list_result = send_list_entries_request(dir_path, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(list_result.rc, FS_OK, "List subdir returned OK")) {
		return false;
	}
	if (!expect_equal_to_buffer(list_result.data_address, (const uint8_t *)"nestedfile.txt\n\0", 16, "Subdir lists nested file")) {
		return false;
	}

	test_begin((char *)"Delete nested file and confirm empty");
	if (!expect_eq_int(send_delete_entry_request(file_path, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_OK, "Delete nested file returned OK")) {
		return false;
	}

	fs_result_list_t list_after_delete = send_list_entries_request(dir_path, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(list_after_delete.rc, FS_OK, "List subdir after delete returned OK")) {
		return false;
	}
	if (!expect_equal_to_buffer(list_after_delete.data_address, (const uint8_t *)"\0", 1, "Subdir empty after delete")) {
		return false;
	}
	output_pass((unsigned char *)"Delete nested file and confirm empty");

	test_begin((char *)"Size reflects number of entries");
	fs_result_size_t size_before = send_get_entry_size_request(dir_path, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(size_before.rc, FS_OK, "Size subdir returned OK")) {
		return false;
	}
	if (!expect_eq_uint32(size_before.size, 0, "Directory size is 0 after delete")) {
		return false;
	}

	fs_result_fileid_t recreate = send_create_file_request(file_path, PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(recreate.rc, FS_OK, "Recreate nested returned OK")) {
		return false;
	}

	fs_result_exists_t exists_result = send_entry_exists_request(file_path, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(exists_result.rc, FS_OK, "Exists returned OK")) {
		return false;
	}
	if (!expect_eq_uint8(exists_result.exists, 1, "Nested file exists")) {
		return false;
	}

	fs_result_size_t size_after = send_get_entry_size_request(dir_path, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(size_after.rc, FS_OK, "Size subdir returned OK")) {
		return false;
	}
	if (!expect_eq_uint32(size_after.size, 1, "Directory size is 1 after recreate")) {
		return false;
	}
	output_pass((unsigned char *)"Size reflects number of entries");

	return true;
}

static bool test_seek_overwrite_and_oob(void) {
	if (!ensure_clean_test_root(fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	const unsigned char path[] = "/__tests/seek.txt";
	const unsigned char write_data[] = "Hello, seL4 File Server!";
	const unsigned char more_write_data[] = "wonderful world!";
	const unsigned char expected_full[] = "Hello, wonderful world!";

	fs_result_fileid_t create_result = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(create_result.rc, FS_OK, "Create seek.txt returned OK")) {
		return false;
	}
	uint32_t fd = create_result.file_id;

	fs_result_write_t write_result = send_write_file_request(fd, sizeof(write_data), write_data, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(write_result.rc, FS_OK, "Write initial returned OK")) {
		return false;
	}
	if (!expect_eq_uint32(write_result.bytes_written, sizeof(write_data), "Bytes written initial")) {
		return false;
	}

	fs_result_size_t size_result = send_get_entry_size_request(path, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(size_result.rc, FS_OK, "Size returned OK")) {
		return false;
	}
	if (!expect_eq_uint32(size_result.size, sizeof(write_data), "Size matches write length")) {
		return false;
	}

	test_begin((char *)"Cursor at end after write; reading should be out-of-bounds");
	fs_result_read_t read_end = send_read_file_request(fd, sizeof(write_data), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(read_end.rc, FS_ERR_OUT_OF_BOUNDS, "Read at end returns OOB")) {
		return false;
	}
	if (!expect_eq_uint32(read_end.bytes_read, 0, "Bytes read at end is 0")) {
		return false;
	}

	if (!expect_eq_int(send_seek_file_request(fd, 1000000, FILE_SERVER_CHANNEL_ID), FS_ERR_OUT_OF_BOUNDS, "Seek beyond end fails")) {
		return false;
	}

	if (!expect_eq_int(send_seek_file_request(fd, 0, FILE_SERVER_CHANNEL_ID), FS_OK, "Seek 0 returned OK")) {
		return false;
	}

	fs_result_read_t read_initial = send_read_file_request(fd, sizeof(write_data), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(read_initial.rc, FS_OK, "Read initial back returned OK")) {
		return false;
	}
	if (!expect_equal_to_buffer(read_initial.data_address, write_data, sizeof(write_data), "Initial readback matches")) {
		return false;
	}

	if (!expect_eq_int(send_seek_file_request(fd, 7, FILE_SERVER_CHANNEL_ID), FS_OK, "Seek middle returned OK")) {
		return false;
	}

	fs_result_write_t overwrite_result = send_write_file_request(fd, sizeof(more_write_data), more_write_data, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(overwrite_result.rc, FS_OK, "Overwrite returned OK")) {
		return false;
	}

	if (!expect_eq_int(send_seek_file_request(fd, 0, FILE_SERVER_CHANNEL_ID), FS_OK, "Seek returned OK")) {
		return false;
	}

	fs_result_read_t full_read = send_read_file_request(fd, sizeof(expected_full), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(full_read.rc, FS_OK, "Read full returned OK")) {
		return false;
	}
	if (!expect_equal_to_buffer(full_read.data_address, expected_full, sizeof(expected_full), "Overwritten content matches")) {
		return false;
	}

	if (!expect_eq_int(send_close_file_request(fd, FILE_SERVER_CHANNEL_ID), FS_OK, "Close returned OK")) {
		return false;
	}

	output_pass((unsigned char *)"Cursor at end after write; reading should be out-of-bounds");
	return true;
}

static bool test_large_write_read(void) {
	if (!ensure_clean_test_root(fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	const unsigned char path[] = "/__tests/large.txt";
	const unsigned char *lots = (const unsigned char *)
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	const uint32_t lots_len = 2791;

	fs_result_fileid_t create_result = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(create_result.rc, FS_OK, "Create large.txt returned OK")) {
		return false;
	}
	uint32_t fd = create_result.file_id;

	fs_result_write_t write_result = send_write_file_request(fd, lots_len, lots, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(write_result.rc, FS_OK, "Large write returned OK")) {
		return false;
	}
	if (!expect_eq_uint32(write_result.bytes_written, lots_len, "Large write bytes")) {
		return false;
	}

	if (!expect_eq_int(send_seek_file_request(fd, 0, FILE_SERVER_CHANNEL_ID), FS_OK, "Seek returned OK")) {
		return false;
	}

	fs_result_read_t read_result = send_read_file_request(fd, lots_len, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(read_result.rc, FS_OK, "Large read returned OK")) {
		return false;
	}
	if (!expect_eq_uint32(read_result.bytes_read, lots_len, "Large read bytes")) {
		return false;
	}
	if (!expect_equal_to_buffer(read_result.data_address, lots, lots_len, "Large readback matches write")) {
		return false;
	}

	return expect_eq_int(send_close_file_request(fd, FILE_SERVER_CHANNEL_ID), FS_OK, "Close returned OK");
}

static bool test_close_fd_errors_and_permissions(void) {
	if (!ensure_clean_test_root(fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	const unsigned char path[] = "/__tests/perm.txt";
	const unsigned char payload[] = "Permission test";

	fs_result_fileid_t create_result = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(create_result.rc, FS_OK, "Create perm.txt returned OK")) {
		return false;
	}
	uint32_t fd = create_result.file_id;

	fs_result_write_t write_result = send_write_file_request(fd, sizeof(payload), payload, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(write_result.rc, FS_OK, "Write payload returned OK")) {
		return false;
	}

	if (!expect_eq_int(send_close_file_request(fd, FILE_SERVER_CHANNEL_ID), FS_OK, "Close returned OK")) {
		return false;
	}

	test_begin((char *)"Closing again should fail");
	if (!expect_eq_int(send_close_file_request(fd, FILE_SERVER_CHANNEL_ID), FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Close again fails with FD not found")) {
		return false;
	}
	output_pass((unsigned char *)"Closing again should fail");

	test_begin((char *)"Reading with closed descriptor should fail");
	fs_result_read_t read_closed = send_read_file_request(fd, sizeof(payload), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(read_closed.rc, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Read closed fails with FD not found")) {
		return false;
	}
	output_pass((unsigned char *)"Reading with closed descriptor should fail");

	test_begin((char *)"Set/get permissions on path");
	if (!fs_test_set_perm_expect_rc(path, PERM_READ, FS_OK, "Set perm", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	fs_result_permissions_t perms = send_get_entry_permissions_request(path, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(perms.rc, FS_OK, "Get perm returned OK")) {
		return false;
	}
	if (!expect_eq_uint8(perms.permissions, PERM_READ, "Permissions are read-only")) {
		return false;
	}
	output_pass((unsigned char *)"Set/get permissions on path");

	test_begin((char *)"Reopen read-only and verify you can't write, but can read what was written");
	fs_result_fileid_t open_read_only = send_open_file_request(READ_OP, path, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(open_read_only.rc, FS_OK, "Open read-only returned OK")) {
		return false;
	}
	uint32_t fd_ro = open_read_only.file_id;

	if (!expect_eq_int(send_seek_file_request(fd_ro, 0, FILE_SERVER_CHANNEL_ID), FS_OK, "Seek returned OK")) {
		return false;
	}

	fs_result_read_t read_result = send_read_file_request(fd_ro, sizeof(payload), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(read_result.rc, FS_OK, "Read returned OK")) {
		return false;
	}
	if (!expect_equal_to_buffer(read_result.data_address, payload, sizeof(payload), "Read-only descriptor reads correct data")) {
		return false;
	}

	fs_result_write_t write_read_only = send_write_file_request(fd_ro, sizeof(payload), payload, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(write_read_only.rc, FS_ERR_PERMISSION, "Write on read-only descriptor fails")) {
		return false;
	}

	if (!expect_eq_int(send_close_file_request(fd_ro, FILE_SERVER_CHANNEL_ID), FS_OK, "Close read-only fd returned OK")) {
		return false;
	}

	output_pass((unsigned char *)"Reopen read-only and verify you can't write, but can read what was written");
	return true;
}

static bool test_deleted_directory_operations_fail(void) {
	if (!ensure_clean_test_root(fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	test_begin((char *)"Create deldir + nested file, keep FD around");
	if (!expect_eq_int(send_create_directory_request((const unsigned char *)"/__tests/deldir", PERM_PUBLIC, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_OK, "Mkdir deldir returned OK")) {
		return false;
	}

	fs_result_fileid_t create_result = send_create_file_request((const unsigned char *)"/__tests/deldir/nestedfile.txt", PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(create_result.rc, FS_OK, "Create nested returned OK")) {
		return false;
	}
	uint32_t fd = create_result.file_id;
	output_pass((unsigned char *)"Create deldir + nested file, keep FD around");

	test_begin((char *)"Delete directory (implementation is expected to remove contained entry too)");
	if (!expect_eq_int(send_delete_entry_request((const unsigned char *)"/__tests/deldir", fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_OK, "Delete deldir returned OK")) {
		return false;
	}
	output_pass((unsigned char *)"Delete directory (implementation is expected to remove contained entry too)");

	test_begin((char *)"Setting permissions on deleted directory should fail");
	if (!fs_test_set_perm_expect_rc((const unsigned char *)"/__tests/deldir", PERM_PUBLIC, FS_ERR_NOT_FOUND, "Set perms on deleted deldir", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Setting permissions on deleted directory should fail");

	test_begin((char *)"Reads on the stale FD should not succeed");
	fs_result_read_t stale_read = send_read_file_request(fd, 1, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_true(stale_read.rc != FS_OK, "Read from file in deleted directory should fail")) {
		return false;
	}
	output_pass((unsigned char *)"Reads on the stale FD should not succeed");

	test_begin((char *)"Exists should report not present");
	fs_result_exists_t exists_result = send_entry_exists_request((const unsigned char *)"/__tests/deldir", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(exists_result.rc, FS_OK, "Exists deldir returned OK")) {
		return false;
	}
	if (!expect_eq_uint8(exists_result.exists, 0, "Deleted directory does not exist")) {
		return false;
	}
	output_pass((unsigned char *)"Exists should report not present");

	test_begin((char *)"List should return not found");
	fs_result_list_t list_result = send_list_entries_request((const unsigned char *)"/__tests/deldir", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(list_result.rc, FS_ERR_NOT_FOUND, "List deleted directory returns NOT_FOUND")) {
		return false;
	}
	output_pass((unsigned char *)"List should return not found");

	return true;
}

static bool test_invalid_inputs_and_edge_cases(void) {
	if (!ensure_clean_test_root(fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	test_begin((char *)"Delete non-existent entry");
	if (!fs_test_delete_expect_rc((const unsigned char *)"/__tests/nope.txt", FS_ERR_NOT_FOUND, "Delete non-existent", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Delete non-existent entry");

	test_begin((char *)"Invalid names: trailing slash gives an empty final component");
	fs_result_fileid_t invalid_file_1 = send_create_file_request((const unsigned char *)"/__tests/", PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(invalid_file_1.rc, FS_ERR_INVALID_PATH, "Create invalid /__tests/ fails")) {
		return false;
	}
	fs_result_fileid_t invalid_file_2 = send_create_file_request((const unsigned char *)"d/f", PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(invalid_file_2.rc, FS_ERR_INVALID_PATH, "Create invalid d/f fails")) {
		return false;
	}
	fs_result_fileid_t invalid_file_3 = send_create_file_request((const unsigned char *)"\0", PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(invalid_file_3.rc, FS_ERR_INVALID_PATH, "Create invalid NUL fails")) {
		return false;
	}
	fs_result_fileid_t invalid_file_4 = send_create_file_request((const unsigned char *)"", PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(invalid_file_4.rc, FS_ERR_INVALID_PATH, "Create invalid empty fails")) {
		return false;
	}
	if (!expect_eq_int(send_create_directory_request((const unsigned char *)"/__tests/", PERM_PUBLIC, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_ERR_INVALID_PATH, "Mkdir invalid /__tests/ fails")) {
		return false;
	}
	if (!expect_eq_int(send_create_directory_request((const unsigned char *)"d/f", PERM_PUBLIC, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_ERR_INVALID_PATH, "Mkdir invalid d/f fails")) {
		return false;
	}
	if (!expect_eq_int(send_create_directory_request((const unsigned char *)"\0", PERM_PUBLIC, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_ERR_INVALID_PATH, "Mkdir invalid NUL fails")) {
		return false;
	}
	if (!expect_eq_int(send_create_directory_request((const unsigned char *)"", PERM_PUBLIC, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_ERR_INVALID_PATH, "Mkdir invalid empty fails")) {
		return false;
	}
	output_pass((unsigned char *)"Invalid names: trailing slash gives an empty final component");

	test_begin((char *)"Root deletion forbidden");
	if (!fs_test_delete_expect_rc((const unsigned char *)"/", FS_ERR_PERMISSION, "Delete root", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Root deletion forbidden");

	test_begin((char *)"Invalid FD");
	fs_result_write_t invalid_write = send_write_file_request(99, 1, (const uint8_t *)"x", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(invalid_write.rc, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Write invalid fd fails")) {
		return false;
	}
	output_pass((unsigned char *)"Invalid FD");

	test_begin((char *)"Max-length name should be invalid");
	fs_result_fileid_t maxlen_file = send_create_file_request((const unsigned char *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PERM_PRIVATE, READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
	if (!expect_eq_int(maxlen_file.rc, FS_ERR_INVALID_PATH, "Create maxlen file invalid")) {
		return false;
	}
	if (!expect_eq_int(send_create_directory_request((const unsigned char *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PERM_PUBLIC, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_ERR_INVALID_PATH, "Mkdir maxlen invalid")) {
		return false;
	}
	output_pass((unsigned char *)"Max-length name should be invalid");

	return true;
}

static void run_tests(void) {
	microkit_debug_puts(OUTPUT_VERBOSITY, ANSI_COLOR_YELLOW);
	microkit_debug_puts(OUTPUT_VERBOSITY, "\n\nStarting synchronous filesystem tests...\n");
	microkit_debug_puts(OUTPUT_VERBOSITY, ANSI_COLOR_RESET);

	run_test_suite("List empty directory", test_list_empty_directory, fs_buffer_base);
	run_test_suite("Create + write + read roundtrip", test_create_write_read_roundtrip, fs_buffer_base);
	run_test_suite("Duplicate create fails", test_duplicate_create_fails, fs_buffer_base);
	run_test_suite("Directory/file conflicts", test_directory_file_conflicts, fs_buffer_base);
	run_test_suite("Nested directory listing + size", test_nested_directory_listing_and_size, fs_buffer_base);
	run_test_suite("Seek overwrite + OOB", test_seek_overwrite_and_oob, fs_buffer_base);
	run_test_suite("Large write/read", test_large_write_read, fs_buffer_base);
	run_test_suite("Close errors + permissions", test_close_fd_errors_and_permissions, fs_buffer_base);
	run_test_suite("Deleted directory operations", test_deleted_directory_operations_fail, fs_buffer_base);
	run_test_suite("Invalid inputs + edge cases", test_invalid_inputs_and_edge_cases, fs_buffer_base);

	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_YELLOW);
	microkit_debug_puts(TEST_VERBOSITY, "\n\nFilesystem tests completed.\n");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
	microkit_debug_puts(TEST_VERBOSITY, "Test Suites passed: ");
	microkit_debug_put32(TEST_VERBOSITY, (uint32_t)tests_passed);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
	microkit_debug_puts(TEST_VERBOSITY, "Test Suites failed: ");
	microkit_debug_put32(TEST_VERBOSITY, (uint32_t)tests_failed);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
}

void notified(microkit_channel ch) {
	(void)ch;
}

void init(void) {
	fs_buffer_base = (uint8_t *)fs_data_base;
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_YELLOW);
	microkit_debug_puts(TEST_VERBOSITY, "TESTING: started\n");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);

	run_tests();

	mark_client_as_finished_running(fs_buffer_base);
	microkit_notify(FILE_SERVER_CHANNEL_ID);
	seL4_Yield();
}
