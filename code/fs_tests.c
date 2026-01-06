#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include "definitions.h"
#include "utils.c"
#include "file_operations.c"

#define FILE_SERVER_CHANNEL_ID 0
#define MAX_FILE_SIZE 0x19000000

uintptr_t file_server_buffer_base;
uint8_t *fs_buffer_base;

void notified(microkit_channel client_id) {}

static int tests_passed = 0;
static int tests_failed = 0;

// Clear the client buffer between tests so previous test data doesn't interfere
static void clear_client_buffer(void) {
    if (!fs_buffer_base) return;
    for (size_t i = 0; i < CLIENT_BUFFER_SIZE; i++) {
        fs_buffer_base[i] = 0;
    }
}

void expect_eq_int(int actual, int expected, const char *name) {
    if (actual == expected) {
        microkit_dbg_puts(ANSI_COLOR_GREEN);
        microkit_dbg_puts("[PASS] ");
        microkit_dbg_puts(ANSI_COLOR_RESET);
        microkit_dbg_puts(name);
        microkit_dbg_puts("\n");
        tests_passed++;
    } else {
        microkit_dbg_puts(ANSI_COLOR_RED);
        microkit_dbg_puts("[FAIL] ");
        microkit_dbg_puts(ANSI_COLOR_RESET);
        microkit_dbg_puts(name);
        microkit_dbg_puts(": expected ");
        microkit_dbg_put32((uint32_t)expected);
        microkit_dbg_puts(" but got ");
        microkit_dbg_put32((uint32_t)actual);
        microkit_dbg_puts("\n");
        tests_failed++;
    }
}

void expect_not_eq_int(int actual, int not_expected, const char *name) {
    if (actual != not_expected) {
        microkit_dbg_puts(ANSI_COLOR_GREEN);
        microkit_dbg_puts("[PASS] ");
        microkit_dbg_puts(ANSI_COLOR_RESET);
        microkit_dbg_puts(name);
        microkit_dbg_puts("\n");
        tests_passed++;
    } else {
        microkit_dbg_puts(ANSI_COLOR_RED);
        microkit_dbg_puts("[FAIL] ");
        microkit_dbg_puts(ANSI_COLOR_RESET);
        microkit_dbg_puts(name);
        microkit_dbg_puts(": did not expect ");
        microkit_dbg_put32((uint32_t)not_expected);
        microkit_dbg_puts("\n");
        tests_failed++;
    }
}

void expect_eq_uint32(uint32_t actual, uint32_t expected, const char *name) {
    if (actual == expected) {
        microkit_dbg_puts(ANSI_COLOR_GREEN);
        microkit_dbg_puts("[PASS] ");
        microkit_dbg_puts(ANSI_COLOR_RESET);
        microkit_dbg_puts(name);
        microkit_dbg_puts("\n");
        tests_passed++;
    } else {
        microkit_dbg_puts(ANSI_COLOR_RED);
        microkit_dbg_puts("[FAIL] ");
        microkit_dbg_puts(ANSI_COLOR_RESET);
        microkit_dbg_puts(name);
        microkit_dbg_puts(": expected ");
        microkit_dbg_put32(expected);
        microkit_dbg_puts(" but got ");
        microkit_dbg_put32(actual);
        microkit_dbg_puts("\n");
        tests_failed++;
    }
}

void expect_eq_uint8(uint8_t actual, uint8_t expected, const char *name) {
    if (actual == expected) {
        microkit_dbg_puts(ANSI_COLOR_GREEN);
        microkit_dbg_puts("[PASS] ");
        microkit_dbg_puts(ANSI_COLOR_RESET);
        microkit_dbg_puts(name);
        microkit_dbg_puts("\n");
        tests_passed++;
    } else {
        microkit_dbg_puts(ANSI_COLOR_RED);
        microkit_dbg_puts("[FAIL] ");
        microkit_dbg_puts(ANSI_COLOR_RESET);
        microkit_dbg_puts(name);
        microkit_dbg_puts(": expected ");
        microkit_dbg_put32((uint32_t)expected);
        microkit_dbg_puts(" but got ");
        microkit_dbg_put32((uint32_t)actual);
        microkit_dbg_puts("\n");
        tests_failed++;
    }
}

void expect_true(bool cond, const char *name) {
    if (cond) {
        microkit_dbg_puts(ANSI_COLOR_GREEN);
        microkit_dbg_puts("[PASS] ");
        microkit_dbg_puts(ANSI_COLOR_RESET);
        microkit_dbg_puts(name);
        microkit_dbg_puts("\n");
        tests_passed++;
    } else {
        microkit_dbg_puts(ANSI_COLOR_RED);
        microkit_dbg_puts("[FAIL] ");
        microkit_dbg_puts(ANSI_COLOR_RESET);
        microkit_dbg_puts(name);
        microkit_dbg_puts("\n");
        tests_failed++;
    }
}

void expect_equal_to_client_buffer(const unsigned char *expected, size_t length, const char *test_message) {
    for (size_t i = 0; i < length; i++) {
        if (fs_buffer_base[i] != expected[i]) {
            microkit_dbg_puts(ANSI_COLOR_RED);
            microkit_dbg_puts("[FAIL] ");
            microkit_dbg_puts(ANSI_COLOR_RESET);
            microkit_dbg_puts(test_message);
            microkit_dbg_puts(": Expected: ");
            for (size_t j = 0; j < length; j++) {
                microkit_dbg_putc(((const char *)expected)[j]);
                if (((const char *)expected)[j] == '\0') {
                    microkit_dbg_putc(',');
                }
            }
            microkit_dbg_puts(", Got: ");
            for (size_t j = 0; j < length; j++) {
                microkit_dbg_putc(((const char *)fs_buffer_base)[j]);
                if (((const char *)fs_buffer_base)[j] == '\0') {
                    microkit_dbg_putc(',');
                }
            }
            microkit_dbg_puts("\n");
            tests_failed++;
            return;
        }
    }
    microkit_dbg_puts(ANSI_COLOR_GREEN);
    microkit_dbg_puts("[PASS] ");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    microkit_dbg_puts(test_message);
    microkit_dbg_puts("\n");
    tests_passed++;
}

void expect_equal_to_buffer(const uint8_t *actual, const uint8_t *expected, size_t length, const char *test_message) {
    for (size_t i = 0; i < length; i++) {
        if (actual[i] != expected[i]) {
            microkit_dbg_puts(ANSI_COLOR_RED);
            microkit_dbg_puts("[FAIL] ");
            microkit_dbg_puts(ANSI_COLOR_RESET);
            microkit_dbg_puts(test_message);
            microkit_dbg_puts(": Expected: ");
            for (size_t j = 0; j < length; j++) {
                microkit_dbg_putc(((const char *)expected)[j]);
            }
            microkit_dbg_puts(", Got: ");
            for (size_t j = 0; j < length; j++) {
                microkit_dbg_putc(((const char *)actual)[j]);
            }
            microkit_dbg_puts("\n");
            tests_failed++;
            return;
        }
    }
    microkit_dbg_puts(ANSI_COLOR_GREEN);
    microkit_dbg_puts("[PASS] ");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    microkit_dbg_puts(test_message);
    microkit_dbg_puts("\n");
    tests_passed++;
}

void expect_eq_strings(const char *actual, const char *expected, const char *test_message) {
    size_t i = 0;
    while (actual[i] != '\0' && expected[i] != '\0') {
        if (actual[i] != expected[i]) {
            microkit_dbg_puts(ANSI_COLOR_RED);
            microkit_dbg_puts("[FAIL] ");
            microkit_dbg_puts(ANSI_COLOR_RESET);
            microkit_dbg_puts(test_message);
            microkit_dbg_puts(": Expected: ");
            microkit_dbg_puts(expected);
            microkit_dbg_puts(", Got: ");
            microkit_dbg_puts(actual);
            microkit_dbg_puts("\n");
            tests_failed++;
            return;
        }
        i++;
    }
    if (actual[i] != expected[i]) {
        microkit_dbg_puts(ANSI_COLOR_RED);
        microkit_dbg_puts("[FAIL] ");
        microkit_dbg_puts(ANSI_COLOR_RESET);
        microkit_dbg_puts(test_message);
        microkit_dbg_puts(": Expected: ");
        microkit_dbg_puts(expected);
        microkit_dbg_puts(", Got: ");
        microkit_dbg_puts(actual);
        microkit_dbg_puts("\n");
        tests_failed++;
        return;
    }
    microkit_dbg_puts(ANSI_COLOR_GREEN);
    microkit_dbg_puts("[PASS] ");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    microkit_dbg_puts(test_message);
    microkit_dbg_puts("\n");
    tests_passed++;
}


void run_tests() {
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nStarting filesystem tests...\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    fs_result_write_t write_res;
    fs_result_read_t read_res;

    // Test cases 

    // List empty filesystem
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files in empty filesystem\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    fs_result_list_t rc_list = send_list_entries_request("/\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_list.rc, FS_OK, "List entries");
    expect_equal_to_client_buffer((const unsigned char *)"\0", 1, "No entries listed");

    // Create a file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    fs_result_fileid_t rc_file = send_create_file_request("/testfile.txt\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_file.rc, FS_OK, "Create file");
    expect_eq_uint32(rc_file.file_id, 0, "File ID is 0");

    // write zero bytes
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Write zero bytes to file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    write_res = send_write_file_request(0, 0, "an", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(write_res.rc, FS_OK, "Write zero bytes to file");
    expect_eq_uint32(write_res.bytes_written, 0, "Bytes written is zero");
    expect_eq_uint32(write_res.new_cursor_position, 0, "Cursor position is unchanged after writing zero bytes");

    // read zero bytes
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Read zero bytes from file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    read_res = send_read_file_request(0, 0, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(read_res.rc, FS_OK, "Read zero bytes from file");
    expect_eq_uint32(read_res.bytes_read, 0, "Bytes read is zero");
    expect_eq_uint32(read_res.new_cursor_position, 0, "Cursor position is unchanged after reading zero bytes");

    // List files again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files after creating '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_list = send_list_entries_request("/\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_list.rc, FS_OK, "List entries");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\n\0", 13, "Entry 'testfile.txt' listed");

    // Create another file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create another file '/testfile1.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_file = send_create_file_request("/testfile1.txt\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_file.rc, FS_OK, "Create file");
    expect_eq_uint32(rc_file.file_id, 1, "File ID is 1");

    // write to second file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Write to file '/testfile1.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    const unsigned char write_data1[] = "Second file data.";
    write_res = send_write_file_request(1, sizeof(write_data1), write_data1, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(write_res.rc, FS_OK, "Write to second file");
    expect_eq_uint32(write_res.bytes_written, sizeof(write_data1), "Bytes written is correct");
    expect_eq_uint32(write_res.new_cursor_position, sizeof(write_data1), "Cursor position is correct");

    // seek to start of second file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Seek to start of file '/testfile1.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    int rc_num = send_seek_file_request(1, 0, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Seek to start of second file");

    // read from second file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Read from file '/testfile1.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    read_res = send_read_file_request(1, sizeof(write_data1), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(read_res.rc, FS_OK, "Read from second file");
    expect_eq_uint32(read_res.bytes_read, sizeof(write_data1), "Bytes read is correct");
    expect_eq_uint32(read_res.new_cursor_position, sizeof(write_data1), "Cursor position is correct after read");
    expect_equal_to_buffer(read_res.data_address, write_data1, sizeof(write_data1), "Data read matches data written");

    // Attempt to create duplicate file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create duplicate file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_file = send_create_file_request("/testfile.txt\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_file.rc, FS_ERR_ALREADY_EXISTS, "Create duplicate file");    

    // Create a directory
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create directory '/testdir'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_create_directory_request("/testdir\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Create directory");

    // open dir as file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Open directory '/testdir' as file\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    fs_result_fileid_t open_dir_as_file_res = send_open_file_request(READ_OP, "/testdir\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(open_dir_as_file_res.rc, FS_ERR_INVALID_PATH, "Open directory as file");

    // create file with name of dir
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file with name of existing directory '/testdir'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_file = send_create_file_request("/testdir\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_file.rc, FS_ERR_ALREADY_EXISTS, "Create file with name of existing directory");

    // List files again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files after creating '/testdir'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_list = send_list_entries_request("/\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_list.rc, FS_OK, "List entries");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\ntestfile1.txt\ntestdir\n\0", 36, "Entries 'testdir', 'testfile1.txt' and 'testfile.txt' listed");

    // Add file to directory
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file '/testdir/nestedfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_file = send_create_file_request("/testdir/nestedfile.txt\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_file.rc, FS_OK, "Create nested file");
    expect_eq_uint32(rc_file.file_id, 2, "Nested File ID is 2");

    // write to nested file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Write to file '/testdir/nestedfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    const unsigned char write_data2[] = "Nested file data.";
    write_res = send_write_file_request(2, sizeof(write_data2), write_data2, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(write_res.rc, FS_OK, "Write to nested file");
    expect_eq_uint32(write_res.bytes_written, sizeof(write_data2), "Bytes written is correct");
    expect_eq_uint32(write_res.new_cursor_position, sizeof(write_data2), "Cursor position is correct");

    // seek to start of nested file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Seek to start of file '/testdir/nestedfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_seek_file_request(2, 0, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Seek to start of nested file");

    // read from nested file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Read from file '/testdir/nestedfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    read_res = send_read_file_request(2, sizeof(write_data2), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(read_res.rc, FS_OK, "Read from nested file");
    expect_eq_uint32(read_res.bytes_read, sizeof(write_data2), "Bytes read is correct");
    expect_eq_uint32(read_res.new_cursor_position, sizeof(write_data2), "Cursor position is correct after read");
    expect_equal_to_buffer(read_res.data_address, write_data2, sizeof(write_data2), "Data read matches data written");

    // List directory contents
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files in '/testdir'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_list = send_list_entries_request("/testdir\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_list.rc, FS_OK, "List entries in directory");
    expect_equal_to_client_buffer((const unsigned char *)"nestedfile.txt\n\0", 16, "Entry 'nestedfile.txt' listed in directory");

    // List root again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files in root directory again\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_list = send_list_entries_request("/\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_list.rc, FS_OK, "List entries in root directory");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\ntestfile1.txt\ntestdir\n\0", 36, "Entries 'testdir', 'testfile1.txt' and 'testfile.txt' listed");

    // Write to file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Write to file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    const unsigned char write_data[] = "Hello, seL4 File Server!";
    write_res = send_write_file_request(0, sizeof(write_data), write_data, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(write_res.rc, FS_OK, "Write to file");
    expect_eq_uint32(write_res.bytes_written, sizeof(write_data), "Bytes written is correct");
    expect_eq_uint32(write_res.new_cursor_position, sizeof(write_data), "Cursor position is correct");

    // Check size of file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Check size of file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    fs_result_size_t fs = send_get_entry_size_request("/testfile.txt\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(fs.rc, FS_OK, "Get size");
    expect_eq_uint32(*((uint32_t *)fs_buffer_base), sizeof(write_data), "Size is correct");

    // Read from file again should error OOB
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Read from file '/testfile.txt' with cursor at end\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    read_res = send_read_file_request(0, sizeof(write_data), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(read_res.rc, FS_ERR_OUT_OF_BOUNDS, "Error as cursor at end");
    expect_eq_uint32(read_res.bytes_read, 0, "Bytes read is zero as cursor at end");
    expect_eq_uint32(read_res.new_cursor_position, sizeof(write_data), "Cursor position is the same as before");

    // Seek beyond end of file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Seek beyond end of file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_seek_file_request(0, MAX_FILE_SIZE, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_ERR_OUT_OF_BOUNDS, "Seek beyond end of file");

    // Seek to start of file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Seek to start of file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_seek_file_request(0, 0, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Seek to start of file");

    // Read from file again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Read from file '/testfile.txt' after seeking to start\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    read_res = send_read_file_request(0, sizeof(write_data), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(read_res.rc, FS_OK, "Read from file after seek");
    expect_eq_uint32(read_res.bytes_read, sizeof(write_data), "Bytes read is correct after seek");
    expect_eq_uint32(read_res.new_cursor_position, sizeof(write_data), "Cursor position is correct after seek");
    expect_equal_to_buffer(read_res.data_address, write_data, sizeof(write_data), "Data read matches data written");

    // Seek to middle of file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Seek to middle of file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_seek_file_request(0, 7, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Seek to middle of file"); 

    // Write more data
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Write more data to file '/testfile.txt' after seeking to middle\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    const unsigned char more_write_data[] = "wonderful world!";
    write_res = send_write_file_request(0, sizeof(more_write_data), more_write_data, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(write_res.rc, FS_OK, "Write more data to file");
    expect_eq_uint32(write_res.bytes_written, sizeof(more_write_data), "Bytes written is correct for more data");
    expect_eq_uint32(write_res.new_cursor_position, 7 + sizeof(more_write_data), "Cursor position is correct after more data write");

    // Seek to start of file again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Seek to start of file '/testfile.txt' again\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_seek_file_request(0, 0, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Seek to start of file again");

    // Read full file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Read full file '/testfile.txt' after writing more data\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    read_res = send_read_file_request(0, write_res.new_cursor_position, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(read_res.rc, FS_OK, "Read full file after more data write");
    expect_eq_uint32(read_res.bytes_read, write_res.new_cursor_position, "Bytes read is correct for full file");
    expect_eq_uint32(read_res.new_cursor_position, write_res.new_cursor_position, "Cursor position is correct for full file");
    const unsigned char full_expected_data[] = "Hello, wonderful world!";
    expect_equal_to_buffer(read_res.data_address, full_expected_data, sizeof(full_expected_data), "Full data read matches expected data");

    // seek to exact end, should be ok
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Seek to exact end of file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_seek_file_request(0, write_res.new_cursor_position, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Seek to exact end of file");

    // List files again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files after deleting '/testfile1.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_list = send_list_entries_request("/\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_list.rc, FS_OK, "List entries");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\ntestfile1.txt\ntestdir\n\0", 22, "Entries 'testdir' and 'testfile.txt' listed");

    // Delete file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Delete file '/testfile1.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_delete_entry_request("/testfile1.txt\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Delete file '/testfile1.txt'");

    // List files again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files after deleting '/testfile1.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_list = send_list_entries_request("/\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_list.rc, FS_OK, "List entries");
    expect_eq_strings((const char *)fs_buffer_base, "testfile.txt\ntestdir\n\0", "Entries 'testdir' and 'testfile.txt' listed");

    // Delete file in directory
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Delete file '/testdir/nestedfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_delete_entry_request("/testdir/nestedfile.txt\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Delete nested file");

    // List directory contents again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files in '/testdir' after deleting 'nestedfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_list = send_list_entries_request("/testdir\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_list.rc, FS_OK, "List entries in directory");
    expect_equal_to_client_buffer((const unsigned char *)"\0", 1, "No entries listed in directory");

    // Get size of dir
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Get size of directory '/testdir'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    fs = send_get_entry_size_request("/testdir\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(fs.rc, FS_OK, "Get size of directory");
    expect_eq_uint32(*((uint32_t *)fs_buffer_base), 0, "Directory size is 0");

    // Add file back to directory
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Re-create file '/testdir/nestedfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_file = send_create_file_request("/testdir/nestedfile.txt\0", 0b110, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_file.rc, FS_OK, "Re-create nested file");
    expect_eq_uint32(rc_file.file_id, 1, "Nested File ID is 1");

    // Check file exists
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Check '/testdir/nestedfile.txt' exists after re-creation\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    fs_result_exists_t fs_exists = send_entry_exists_request("/testdir/nestedfile.txt\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(fs_exists.rc, FS_OK, "Check entry exists");
    expect_eq_uint8(fs_buffer_base[0], 1, "Entry exists");

    // Get size of dir again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Get size of directory '/testdir' after adding 'nestedfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    fs = send_get_entry_size_request("/testdir\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(fs.rc, FS_OK, "Get size of directory");
    expect_eq_uint32(*((uint32_t *)fs_buffer_base), 1, "Directory size is 1");

    // List files again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files before deleting '/testdir'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_list = send_list_entries_request("/\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_list.rc, FS_OK, "List entries");
    expect_eq_strings((const char *)fs_buffer_base, "testfile.txt\ntestdir\n\0", "Entries 'testdir' and 'testfile.txt' listed");

    // Delete directory
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Delete directory '/testdir'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_delete_entry_request("/testdir\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Delete directory '/testdir'");

    // List files again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files after deleting '/testdir'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_list = send_list_entries_request("/\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_list.rc, FS_OK, "List entries");
    expect_eq_strings((const char *)fs_buffer_base, "testfile.txt\n\0", "Entry 'testfile.txt' listed");

    // try setting permissions on deleted directory
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Set permissions of deleted directory '/testdir' to 0b111\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_set_entry_permissions_request("/testdir\0", 0b111, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_ERR_NOT_FOUND, "Set permissions on deleted directory");

    // test reading from file in deleted directory
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Read from file '/testdir/nestedfile.txt' in deleted directory\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    read_res = send_read_file_request(1, sizeof(write_data), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_not_eq_int(read_res.rc, FS_OK, "Read from file in deleted directory");

    // Check directory doesnt exist
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Check '/testdir' does not exist after deletion\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    fs_exists = send_entry_exists_request("/testdir\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(fs_exists.rc, FS_OK, "Check entry does not exist");
    expect_eq_uint8(fs_buffer_base[0], 0, "Entry does not exist");

    // List deleted directory contents
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files in deleted directory '/testdir'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_list = send_list_entries_request("/testdir\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_list.rc, FS_ERR_NOT_FOUND, "List entries in deleted directory");

    // seek to start of file again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Seek to start of file '/testfile.txt' again\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_seek_file_request(0, 0, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Seek to start of file again");

    //write a lot - make blocks small
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Write more data to file '/testfile.txt' after seeking to middle\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    const unsigned char *lots = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_res = send_write_file_request(0, 8261, lots, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(write_res.rc, FS_OK, "Write more data to file");
    expect_eq_uint32(write_res.bytes_written, 8261, "Bytes written is correct for more data");
    expect_eq_uint32(write_res.new_cursor_position, 8261, "Cursor position is correct after more data write");

    // seek to start of file again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Seek to start of file '/testfile.txt' again\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_seek_file_request(0, 0, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Seek to start of file again");

    //read a lot - make blocks small
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Read full file '/testfile.txt' after writing more data\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    read_res = send_read_file_request(0, write_res.new_cursor_position, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(read_res.rc, FS_OK, "Read full file after more data write");
    expect_eq_uint32(read_res.bytes_read, 8261, "Bytes read is correct for full file");
    expect_eq_uint32(read_res.new_cursor_position, 8261, "Cursor position is correct for full file");
    expect_equal_to_buffer(read_res.data_address, lots, 8261, "Data read matches expected data");

    // Close file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Close file ID 0 ('/testfile.txt')\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_close_file_request(0, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Close file ID 0");

    // Try closing again
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Close file ID 0 ('/testfile.txt') again\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_close_file_request(0, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Close file ID 0 again");

    // Try reading closed file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Read from closed file ID 0 ('/testfile.txt')\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    read_res = send_read_file_request(0, sizeof(write_data), fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(read_res.rc, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Read from closed file ID 0");

    // Set permissions
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Set permissions of '/testfile.txt' to 0b100\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_set_entry_permissions_request("/testfile.txt\0", READ_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Set permissions");

    // Get permissions
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Get permissions of '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    fs_result_permissions_t fs_result_permissions = send_get_entry_permissions_request("/testfile.txt\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(fs_result_permissions.rc, FS_OK, "Get permissions");
    expect_eq_uint8((uint8_t)fs_buffer_base[0], READ_OP, "Permissions are 0b100");

    // Reopen file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Reopen file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    fs_result_fileid_t reopen_res = send_open_file_request(READ_OP, "/testfile.txt\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(reopen_res.rc, FS_OK, "Reopen file");
    expect_eq_uint32(reopen_res.file_id, 0, "File ID is 0");

    // Check contents after reopen and seeking to start
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Check contents of '/testfile.txt' after reopening\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_seek_file_request(0, 0, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_OK, "Seek to start of file after reopen");
    read_res = send_read_file_request(0, 8261, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(read_res.rc, FS_OK, "Read from file after reopen");
    expect_eq_uint32(read_res.bytes_read, 8261, "Bytes read is correct after reopen");
    expect_eq_uint32(read_res.new_cursor_position, 8261, "Cursor position is correct after reopen");
    expect_equal_to_buffer(read_res.data_address, lots, 8261, "Data read matches data written after reopen");

    // Check cant write to read-only opened file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Attempt to write to read-only opened file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    write_res = send_write_file_request(0, sizeof(write_data), write_data, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(write_res.rc, FS_ERR_PERMISSION, "Attempt to write to read-only opened file");
    
    // delete non-existent file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Delete non-existent file '/nonexistent.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_delete_entry_request("/nonexistent.txt\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_ERR_NOT_FOUND, "Delete non-existent file");

    // create file with invalid name, \0, /, maxlength
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file with invalid name '//df'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_file = send_create_file_request("//df\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_file.rc, FS_ERR_INVALID_PATH, "Create file with invalid name");

    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file with invalid name 'd/f'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_file = send_create_file_request("d/f\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_file.rc, FS_ERR_INVALID_PATH, "Create file with invalid name");

    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file with invalid name '0'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_file = send_create_file_request("\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_file.rc, FS_ERR_INVALID_PATH, "Create file with invalid name");

    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file with invalid name ''\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_file = send_create_file_request("", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_file.rc, FS_ERR_INVALID_PATH, "Create file with invalid name");


    // create directory with invalid name, ''
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create directory with invalid name '//df'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_create_directory_request("//df\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);

    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create directory with invalid name 'd/f'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_create_directory_request("d/f\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);

    expect_eq_int(rc_num, FS_ERR_INVALID_PATH, "Create directory with invalid name");
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create directory with invalid name '0'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_create_directory_request("\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);

    expect_eq_int(rc_num, FS_ERR_INVALID_PATH, "Create directory with invalid name");
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create directory with invalid name ''\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_create_directory_request("", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_ERR_INVALID_PATH, "Create directory with invalid name");

    // delete root
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Delete root directory '/'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_delete_entry_request("/\0", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_ERR_PERMISSION, "Delete root directory");

    // create dir with name of file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create directory with name of existing file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_create_directory_request("/testfile.txt\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_ERR_ALREADY_EXISTS, "Create directory with name of existing file");

    // write on invalid file id
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Write to invalid file ID 99\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    write_res = send_write_file_request(99, sizeof(write_data), write_data, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(write_res.rc, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Write to invalid file ID");

    // seek to negative position
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Seek to negative position in file '/testfile.txt'\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_seek_file_request(0, (uint32_t)(-1), FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_ERR_OUT_OF_BOUNDS, "Seek to negative position in file");

    // create file with max length name
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file with maximum length name\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_file = send_create_file_request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_file.rc, FS_ERR_INVALID_PATH, "Create file with maximum length name");

    // create directory with max length name
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create directory with maximum length name\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_client_buffer();
    rc_num = send_create_directory_request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0", READ_WRITE_OP, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc_num, FS_ERR_INVALID_PATH, "Create directory with maximum length name");

    
    //block table full - make block table small
    //add max number of files to dir - make child entries massive
    //max open files - make max open files small
    //i node table full - make i node table small

    // Permission tests

    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nFilesystem tests completed.\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    microkit_dbg_puts("Tests passed: ");
    microkit_dbg_put32((uint32_t)tests_passed);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("Tests failed: ");
    microkit_dbg_put32((uint32_t)tests_failed);
    microkit_dbg_puts("\n");
}

void init(void) {
    fs_buffer_base = (uint8_t *)file_server_buffer_base;
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("TESTING: started\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    run_tests();
}
