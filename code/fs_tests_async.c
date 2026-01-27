#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include "definitions.h"
#include "utils.c"
#include "file_operations_async.c"

uintptr_t file_server_submission_queue_base;
uintptr_t file_server_completion_queue_base;
uintptr_t file_server_submission_buffer_base;
uintptr_t file_server_completion_buffer_base;
uintptr_t buffer_table_base;

submission_queue_entry_t *file_server_submission_queue;
completion_queue_entry_t *file_server_completion_queue;
uint8_t *file_server_submission_buffer;
uint8_t *file_server_completion_buffer;
uint8_t *buffer_table; 
file_server_interface_t file_server_interface;


#define NUMBER_OF_BUFFERS 64
#define CLIENT_BUFFER_SIZE 0x1000
#define MAX_QUEUE_ENTRIES 64 //TODO: this can be higher

void notified(microkit_channel client_id) {}

static int tests_passed = 0;
static int tests_failed = 0;

static void clear_all_client_buffers(void) {
    //TODO
    return;
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

void expect_equal_to_client_buffer(const unsigned char *expected, size_t length, const char *test_message, int buffer_index) {
    uint8_t *fs_buffer_base = COMPLETION_BUFFER(file_server_completion_buffer, buffer_index);
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

void test_begin(char *msg) {
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n=== ");
    microkit_dbg_puts(msg);
    microkit_dbg_puts(" ===\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_all_client_buffers();
}

void run_tests() {
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nStarting filesystem tests...\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_all_client_buffers();
    fs_result_t rc;

    // Test cases 
    completion_queue_entry_t rc_fail;
    rc = get_next_completion_entry(&file_server_interface, &rc_fail);
    expect_eq_int(rc, FS_ERROR_NO_COMPLETION_ENTRIES_AVAILABLE, "No completion entries available initially");

    // List empty filesystem
    test_begin("List files in empty filesystem");
    rc = send_list_entries_request("/\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "List entries");
    notify_file_server(&file_server_interface, 1);
    // print submission tail
    microkit_dbg_puts("Submission queue tail after listing entries: ");
    uint32_t *submission_tail = SUBMISSION_QUEUE_TAIL(file_server_interface.file_server_submission_queue);
    microkit_dbg_put32(*submission_tail);
    microkit_dbg_puts("\n");
    completion_queue_entry_t rc_list;
    rc = get_next_completion_entry(&file_server_interface, &rc_list);
    microkit_dbg_puts("Submission queue tail after listing entries: ");
    submission_tail = SUBMISSION_QUEUE_TAIL(file_server_interface.file_server_submission_queue);
    microkit_dbg_put32(*submission_tail);
    microkit_dbg_puts("\n");
    expect_eq_int(rc, FS_OK, "Get completion entry for list entries");
    expect_eq_uint32(rc_list.return_code, FS_OK, "List entries return code is OK");
    expect_equal_to_client_buffer((const unsigned char *)"\0", 1, "No entries listed", rc_list.buffer_index);

    // Create a file
    test_begin("Create file '/testfile.txt'");
    rc = send_create_file_request("/testfile.txt\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Create file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_file;
    rc = get_next_completion_entry(&file_server_interface, &rc_file);
    expect_eq_int(rc, FS_OK, "Get completion entry for create file");
    expect_eq_uint32(rc_file.return_code, FS_OK, "Create file return code is OK");
    expect_eq_uint32(rc_file.parameter1, 0, "File ID is 0");

    // Write zero bytes
    test_begin("Write zero bytes to file '/testfile.txt'");
    rc = send_write_file_request(0, 0, (const uint8_t *)"an", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue write zero bytes");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_write0;
    rc = get_next_completion_entry(&file_server_interface, &rc_write0);
    expect_eq_int(rc, FS_OK, "Get completion entry for write zero");
    expect_eq_uint32(rc_write0.return_code, FS_OK, "Write zero return code is OK");
    expect_eq_uint32(rc_write0.parameter1, 0, "Bytes written is zero");
    expect_eq_uint32(rc_write0.parameter2, 0, "Cursor unchanged after writing zero");

    // Read zero bytes
    test_begin("Read zero bytes from file '/testfile.txt'");
    rc = send_read_file_request(0, 0, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue read zero bytes");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_read0;
    rc = get_next_completion_entry(&file_server_interface, &rc_read0);
    expect_eq_int(rc, FS_OK, "Get completion entry for read zero");
    expect_eq_uint32(rc_read0.return_code, FS_OK, "Read zero return code is OK");
    expect_eq_uint32(rc_read0.parameter1, 0, "Bytes read is zero");
    expect_eq_uint32(rc_read0.parameter2, 0, "Cursor unchanged after reading zero");

    // List files again
    test_begin("List files after creating '/testfile.txt'");
    rc = send_list_entries_request("/\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue list entries");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_list2;
    rc = get_next_completion_entry(&file_server_interface, &rc_list2);
    expect_eq_int(rc, FS_OK, "Get completion entry for list entries");
    expect_eq_uint32(rc_list2.return_code, FS_OK, "List return code is OK");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\n\0", 13, "Entry 'testfile.txt' listed", rc_list2.buffer_index);

    // Create another file
    test_begin("Create another file '/testfile1.txt'");
    rc = send_create_file_request("/testfile1.txt\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue create second file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_file2;
    rc = get_next_completion_entry(&file_server_interface, &rc_file2);
    expect_eq_int(rc, FS_OK, "Get completion entry for create second file");
    expect_eq_uint32(rc_file2.return_code, FS_OK, "Create second file return code is OK");
    expect_eq_uint32(rc_file2.parameter1, 1, "File ID is 1");

    // Write to second file
    test_begin("Write to file '/testfile1.txt'");
    const unsigned char write_data1[] = "Second file data.";
    rc = send_write_file_request(1, sizeof(write_data1), write_data1, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue write to second file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_write1;
    rc = get_next_completion_entry(&file_server_interface, &rc_write1);
    expect_eq_int(rc, FS_OK, "Get completion entry for write second file");
    expect_eq_uint32(rc_write1.return_code, FS_OK, "Write second file return code is OK");
    expect_eq_uint32(rc_write1.parameter1, sizeof(write_data1), "Bytes written is correct");
    expect_eq_uint32(rc_write1.parameter2, sizeof(write_data1), "Cursor position is correct");

    // Seek to start of second file
    test_begin("Seek to start of file '/testfile1.txt'");
    rc = send_seek_file_request(1, 0, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue seek start second file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_seek1;
    rc = get_next_completion_entry(&file_server_interface, &rc_seek1);
    expect_eq_int(rc, FS_OK, "Get completion entry for seek second file");
    expect_eq_uint32(rc_seek1.return_code, FS_OK, "Seek to start of second file");

    // Read from second file
    test_begin("Read from file '/testfile1.txt'");
    rc = send_read_file_request(1, sizeof(write_data1), &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue read second file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_read1;
    rc = get_next_completion_entry(&file_server_interface, &rc_read1);
    expect_eq_int(rc, FS_OK, "Get completion entry for read second file");
    expect_eq_uint32(rc_read1.return_code, FS_OK, "Read return code is OK");
    expect_eq_uint32(rc_read1.parameter1, sizeof(write_data1), "Bytes read is correct");
    expect_eq_uint32(rc_read1.parameter2, sizeof(write_data1), "Cursor position is correct after read");
    expect_equal_to_client_buffer(write_data1, sizeof(write_data1), "Data read matches data written", rc_read1.buffer_index);

    // Attempt to create duplicate file
    test_begin("Create duplicate file '/testfile.txt'");
    rc = send_create_file_request("/testfile.txt\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue create duplicate");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_dup;
    rc = get_next_completion_entry(&file_server_interface, &rc_dup);
    expect_eq_int(rc, FS_OK, "Get completion entry for duplicate");
    expect_eq_uint32(rc_dup.return_code, FS_ERR_ALREADY_EXISTS, "Create duplicate should fail");

    // Create a directory
    test_begin("Create directory '/testdir'");
    rc = send_create_directory_request("/testdir\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue create directory");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_mkdir;
    rc = get_next_completion_entry(&file_server_interface, &rc_mkdir);
    expect_eq_int(rc, FS_OK, "Get completion entry for mkdir");
    expect_eq_uint32(rc_mkdir.return_code, FS_OK, "Create directory return code is OK");

    // open dir as file
    test_begin("Open directory '/testdir' as file");
    rc = send_open_file_request(READ_OP, "/testdir\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue open dir as file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_open_dir_as_file;
    rc = get_next_completion_entry(&file_server_interface, &rc_open_dir_as_file);
    expect_eq_int(rc, FS_OK, "Get completion entry for open dir as file");
    expect_eq_uint32(rc_open_dir_as_file.return_code, FS_ERR_INVALID_PATH, "Open directory as file should fail");

    // create file with name of dir
    test_begin("Create file with name of existing directory '/testdir'");
    rc = send_create_file_request("/testdir\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue create file named dir");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_file_named_dir;
    rc = get_next_completion_entry(&file_server_interface, &rc_file_named_dir);
    expect_eq_int(rc, FS_OK, "Get completion entry for create file named dir");
    expect_eq_uint32(rc_file_named_dir.return_code, FS_ERR_ALREADY_EXISTS, "Create file with name of existing directory should fail");

    // List files again
    test_begin("List files after creating '/testdir'");
    rc = send_list_entries_request("/\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue list entries");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_list3;
    rc = get_next_completion_entry(&file_server_interface, &rc_list3);
    expect_eq_int(rc, FS_OK, "Get completion entry for list entries");
    expect_eq_uint32(rc_list3.return_code, FS_OK, "List return code is OK");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\ntestfile1.txt\ntestdir\n\0", 36, "Entries 'testdir', 'testfile1.txt' and 'testfile.txt' listed", rc_list3.buffer_index);

    // Add file to directory
    test_begin("Create file '/testdir/nestedfile.txt'");
    rc = send_create_file_request("/testdir/nestedfile.txt\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue create nested file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_file_nested;
    rc = get_next_completion_entry(&file_server_interface, &rc_file_nested);
    expect_eq_int(rc, FS_OK, "Get completion entry for create nested file");
    expect_eq_uint32(rc_file_nested.return_code, FS_OK, "Create nested file return code is OK");
    expect_eq_uint32(rc_file_nested.parameter1, 2, "Nested File ID is 2");

    // write to nested file
    test_begin("Write to file '/testdir/nestedfile.txt'");
    const unsigned char write_data2[] = "Nested file data.";
    rc = send_write_file_request(2, sizeof(write_data2), write_data2, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue write to nested file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_write2;
    rc = get_next_completion_entry(&file_server_interface, &rc_write2);
    expect_eq_int(rc, FS_OK, "Get completion entry for write nested file");
    expect_eq_uint32(rc_write2.return_code, FS_OK, "Write nested return code is OK");
    expect_eq_uint32(rc_write2.parameter1, sizeof(write_data2), "Bytes written is correct");
    expect_eq_uint32(rc_write2.parameter2, sizeof(write_data2), "Cursor position is correct");

    // seek to start of nested file
    test_begin("Seek to start of file '/testdir/nestedfile.txt'");
    rc = send_seek_file_request(2, 0, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue seek start nested");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_seek2;
    rc = get_next_completion_entry(&file_server_interface, &rc_seek2);
    expect_eq_int(rc, FS_OK, "Get completion entry for seek nested");
    expect_eq_uint32(rc_seek2.return_code, FS_OK, "Seek to start of nested file");

    // read from nested file
    test_begin("Read from file '/testdir/nestedfile.txt'");
    rc = send_read_file_request(2, sizeof(write_data2), &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue read nested file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_read2;
    rc = get_next_completion_entry(&file_server_interface, &rc_read2);
    expect_eq_int(rc, FS_OK, "Get completion entry for read nested file");
    expect_eq_uint32(rc_read2.return_code, FS_OK, "Read nested return code is OK");
    expect_eq_uint32(rc_read2.parameter1, sizeof(write_data2), "Bytes read is correct");
    expect_eq_uint32(rc_read2.parameter2, sizeof(write_data2), "Cursor position is correct after read");
    expect_equal_to_client_buffer(write_data2, sizeof(write_data2), "Data read matches data written", rc_read2.buffer_index);

    // List directory contents
    test_begin("List files in '/testdir'");
    rc = send_list_entries_request("/testdir\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue list entries in directory");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_list_dir1;
    rc = get_next_completion_entry(&file_server_interface, &rc_list_dir1);
    expect_eq_int(rc, FS_OK, "Get completion entry for list dir");
    expect_eq_uint32(rc_list_dir1.return_code, FS_OK, "List dir return code is OK");
    expect_equal_to_client_buffer((const unsigned char *)"nestedfile.txt\n\0", 16, "Entry 'nestedfile.txt' listed in directory", rc_list_dir1.buffer_index);

    // List root again
    test_begin("List files in root directory again");
    rc = send_list_entries_request("/\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue list entries in root");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_list_root2;
    rc = get_next_completion_entry(&file_server_interface, &rc_list_root2);
    expect_eq_int(rc, FS_OK, "Get completion entry for list root");
    expect_eq_uint32(rc_list_root2.return_code, FS_OK, "List root return code is OK");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\ntestfile1.txt\ntestdir\n\0", 36, "Entries 'testdir', 'testfile1.txt' and 'testfile.txt' listed", rc_list_root2.buffer_index);

    // Write to file
    test_begin("Write to file '/testfile.txt'");
    const unsigned char write_data[] = "Hello, seL4 File Server!";
    rc = send_write_file_request(0, sizeof(write_data), write_data, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue write to file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_write0_full;
    rc = get_next_completion_entry(&file_server_interface, &rc_write0_full);
    expect_eq_int(rc, FS_OK, "Get completion entry for write file 0");
    expect_eq_uint32(rc_write0_full.return_code, FS_OK, "Write return code is OK");
    expect_eq_uint32(rc_write0_full.parameter1, sizeof(write_data), "Bytes written is correct");
    expect_eq_uint32(rc_write0_full.parameter2, sizeof(write_data), "Cursor position is correct");

    // Check size of file
    test_begin("Check size of file '/testfile.txt'");
    rc = send_get_entry_size_request("/testfile.txt\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue get size");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_size0;
    rc = get_next_completion_entry(&file_server_interface, &rc_size0);
    expect_eq_int(rc, FS_OK, "Get completion entry for get size");
    expect_eq_uint32(rc_size0.return_code, FS_OK, "Get size return code is OK");
    expect_eq_uint32(rc_size0.parameter1, sizeof(write_data), "Size is correct");

    // Read from file again should error OOB
    test_begin("Read from file '/testfile.txt' with cursor at end");
    rc = send_read_file_request(0, sizeof(write_data), &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue read at end");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_read_oob0;
    rc = get_next_completion_entry(&file_server_interface, &rc_read_oob0);
    expect_eq_int(rc, FS_OK, "Get completion entry for read at end");
    expect_eq_uint32(rc_read_oob0.return_code, FS_ERR_OUT_OF_BOUNDS, "Read at end should be OOB");
    expect_eq_uint32(rc_read_oob0.parameter1, 0, "Bytes read is zero at end");
    expect_eq_uint32(rc_read_oob0.parameter2, sizeof(write_data), "Cursor unchanged at end");

    // Seek beyond end of file
    test_begin("Seek beyond end of file '/testfile.txt'");
    rc = send_seek_file_request(0, 1000000, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue seek beyond end");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_seek_oob0;
    rc = get_next_completion_entry(&file_server_interface, &rc_seek_oob0);
    expect_eq_int(rc, FS_OK, "Get completion entry for seek beyond end");
    expect_eq_uint32(rc_seek_oob0.return_code, FS_ERR_OUT_OF_BOUNDS, "Seek beyond end should fail");

    // Seek to start of file
    test_begin("Seek to start of file '/testfile.txt'");
    rc = send_seek_file_request(0, 0, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue seek start");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_seek_start0;
    rc = get_next_completion_entry(&file_server_interface, &rc_seek_start0);
    expect_eq_int(rc, FS_OK, "Get completion entry for seek start");
    expect_eq_uint32(rc_seek_start0.return_code, FS_OK, "Seek to start of file");

    // Read from file again
    test_begin("Read from file '/testfile.txt' after seeking to start");
    rc = send_read_file_request(0, sizeof(write_data), &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue read after seek");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_read_after_seek0;
    rc = get_next_completion_entry(&file_server_interface, &rc_read_after_seek0);
    expect_eq_int(rc, FS_OK, "Get completion entry for read after seek");
    expect_eq_uint32(rc_read_after_seek0.return_code, FS_OK, "Read after seek return code is OK");
    expect_eq_uint32(rc_read_after_seek0.parameter1, sizeof(write_data), "Bytes read correct after seek");
    expect_eq_uint32(rc_read_after_seek0.parameter2, sizeof(write_data), "Cursor correct after seek");
    expect_equal_to_client_buffer(write_data, sizeof(write_data), "Data read matches data written", rc_read_after_seek0.buffer_index);

    // Seek to middle of file
    test_begin("Seek to middle of file '/testfile.txt'");
    rc = send_seek_file_request(0, 7, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue seek middle"); 
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_seek_mid0;
    rc = get_next_completion_entry(&file_server_interface, &rc_seek_mid0);
    expect_eq_int(rc, FS_OK, "Get completion entry for seek middle");
    expect_eq_uint32(rc_seek_mid0.return_code, FS_OK, "Seek middle return code is OK");

    // Write more data
    test_begin("Write more data to file '/testfile.txt' after seeking to middle");
    const unsigned char more_write_data[] = "wonderful world!";
    rc = send_write_file_request(0, sizeof(more_write_data), more_write_data, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue write more data");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_write_more0;
    rc = get_next_completion_entry(&file_server_interface, &rc_write_more0);
    expect_eq_int(rc, FS_OK, "Get completion entry for write more data");
    expect_eq_uint32(rc_write_more0.return_code, FS_OK, "Write more return code is OK");
    expect_eq_uint32(rc_write_more0.parameter1, sizeof(more_write_data), "Bytes written correct for more data");
    expect_eq_uint32(rc_write_more0.parameter2, 7 + sizeof(more_write_data), "Cursor correct after more data");

    // Seek to start of file again
    test_begin("Seek to start of file '/testfile.txt' again");
    rc = send_seek_file_request(0, 0, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue seek start again");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_seek_start_again0;
    rc = get_next_completion_entry(&file_server_interface, &rc_seek_start_again0);
    expect_eq_int(rc, FS_OK, "Get completion entry for seek start again");
    expect_eq_uint32(rc_seek_start_again0.return_code, FS_OK, "Seek start again return code is OK");

    // Read full file
    test_begin("Read full file '/testfile.txt' after writing more data");
    rc = send_read_file_request(0, rc_write_more0.parameter2, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue read full file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_read_full0;
    rc = get_next_completion_entry(&file_server_interface, &rc_read_full0);
    expect_eq_int(rc, FS_OK, "Get completion entry for read full file");
    expect_eq_uint32(rc_read_full0.return_code, FS_OK, "Read full return code is OK");
    expect_eq_uint32(rc_read_full0.parameter1, rc_write_more0.parameter2, "Bytes read correct for full file");
    expect_eq_uint32(rc_read_full0.parameter2, rc_write_more0.parameter2, "Cursor correct for full file");
    const unsigned char full_expected_data[] = "Hello, wonderful world!";
    expect_equal_to_client_buffer(full_expected_data, sizeof(full_expected_data), "Full data read matches expected data", rc_read_full0.buffer_index);

    // seek to exact end, should be ok
    test_begin("Seek to exact end of file '/testfile.txt'");
    rc = send_seek_file_request(0, rc_read_full0.parameter2, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue seek exact end");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_seek_exact_end0;
    rc = get_next_completion_entry(&file_server_interface, &rc_seek_exact_end0);
    expect_eq_int(rc, FS_OK, "Get completion for seek exact end");
    expect_eq_uint32(rc_seek_exact_end0.return_code, FS_OK, "Seek to exact end of file");

    // List files again
    test_begin("List files at root before deleting '/testfile1.txt'");
    rc = send_list_entries_request("/\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue list entries");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_list_before_delete1;
    rc = get_next_completion_entry(&file_server_interface, &rc_list_before_delete1);
    expect_eq_int(rc, FS_OK, "Get completion for list before delete");
    expect_eq_uint32(rc_list_before_delete1.return_code, FS_OK, "List before delete returned OK");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\ntestfile1.txt\ntestdir\n\0", 22, "Entries 'testdir' and 'testfile.txt' listed", rc_list_before_delete1.buffer_index);

    // Delete file
    test_begin("Delete file '/testfile1.txt'");
    rc = send_delete_entry_request("/testfile1.txt\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue delete '/testfile1.txt'");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_delete_file1;
    rc = get_next_completion_entry(&file_server_interface, &rc_delete_file1);
    expect_eq_int(rc, FS_OK, "Get completion for delete file1");
    expect_eq_uint32(rc_delete_file1.return_code, FS_OK, "Delete file '/testfile1.txt'");

    // List files again
    test_begin("List files after deleting '/testfile1.txt'");
    rc = send_list_entries_request("/\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue list entries after delete");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_list_after_delete1;
    rc = get_next_completion_entry(&file_server_interface, &rc_list_after_delete1);
    expect_eq_int(rc, FS_OK, "Get completion for list after delete");
    expect_eq_uint32(rc_list_after_delete1.return_code, FS_OK, "List after delete returned OK");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\ntestdir\n\0", 17, "Entries 'testdir' and 'testfile.txt' listed", rc_list_after_delete1.buffer_index);

    // Delete file in directory
    test_begin("Delete file '/testdir/nestedfile.txt'");
    rc = send_delete_entry_request("/testdir/nestedfile.txt\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue delete nested file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_delete_nested;
    rc = get_next_completion_entry(&file_server_interface, &rc_delete_nested);
    expect_eq_int(rc, FS_OK, "Get completion for delete nested");
    expect_eq_uint32(rc_delete_nested.return_code, FS_OK, "Delete nested file returned OK");

    // List directory contents again
    test_begin("List files in '/testdir' after deleting 'nestedfile.txt'");
    rc = send_list_entries_request("/testdir\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue list entries in directory");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_list_testdir_after_delete;
    rc = get_next_completion_entry(&file_server_interface, &rc_list_testdir_after_delete);
    expect_eq_int(rc, FS_OK, "Get completion for list '/testdir'");
    expect_eq_uint32(rc_list_testdir_after_delete.return_code, FS_OK, "List '/testdir' returned OK");
    expect_equal_to_client_buffer((const unsigned char *)"\0", 1, "No entries listed in directory", rc_list_testdir_after_delete.buffer_index);

    // Get size of dir
    test_begin("Get size of directory '/testdir'");
    rc = send_get_entry_size_request("/testdir\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue get size of directory");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_size_dir0;
    rc = get_next_completion_entry(&file_server_interface, &rc_size_dir0);
    expect_eq_int(rc, FS_OK, "Get completion for size '/testdir'");
    expect_eq_uint32(rc_size_dir0.return_code, FS_OK, "Get size dir returned OK");
    expect_eq_uint32(rc_size_dir0.parameter1, 0, "Directory size is 0");

    // Add file back to directory
    test_begin("Re-create file '/testdir/nestedfile.txt'");
    rc = send_create_file_request("/testdir/nestedfile.txt\0", 0b110, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue re-create nested file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_recreate_nested;
    rc = get_next_completion_entry(&file_server_interface, &rc_recreate_nested);
    expect_eq_int(rc, FS_OK, "Get completion for re-create nested");
    expect_eq_uint32(rc_recreate_nested.return_code, FS_OK, "Re-create nested returned OK");
    expect_eq_uint32(rc_recreate_nested.parameter1, 1, "Nested File ID is 1");

    // Check file exists
    test_begin("Check '/testdir/nestedfile.txt' exists after re-creation");
    rc = send_entry_exists_request("/testdir/nestedfile.txt\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue entry exists");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_exists_nested;
    rc = get_next_completion_entry(&file_server_interface, &rc_exists_nested);
    expect_eq_int(rc, FS_OK, "Get completion for entry exists");
    expect_eq_uint32(rc_exists_nested.return_code, FS_OK, "Entry exists returned OK");
    expect_eq_uint32(rc_exists_nested.parameter1, 1, "Entry exists");

    // Get size of dir again
    test_begin("Get size of directory '/testdir' after adding 'nestedfile.txt'");
    rc = send_get_entry_size_request("/testdir\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue get size of directory");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_size_dir1;
    rc = get_next_completion_entry(&file_server_interface, &rc_size_dir1);
    expect_eq_int(rc, FS_OK, "Get completion for size '/testdir' again");
    expect_eq_uint32(rc_size_dir1.return_code, FS_OK, "Get size dir returned OK");
    expect_eq_uint32(rc_size_dir1.parameter1, 1, "Directory size is 1");

    // List files again
    test_begin("List files before deleting '/testdir'");
    rc = send_list_entries_request("/\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue list entries");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_list_before_del_dir;
    rc = get_next_completion_entry(&file_server_interface, &rc_list_before_del_dir);
    expect_eq_int(rc, FS_OK, "Get completion for list before deleting dir");
    expect_eq_uint32(rc_list_before_del_dir.return_code, FS_OK, "List before deleting dir returned OK");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\ntestdir\n\0", 17, "Entries 'testdir' and 'testfile.txt' listed", rc_list_before_del_dir.buffer_index);

    // Delete directory
    test_begin("Delete directory '/testdir'");
    rc = send_delete_entry_request("/testdir\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue delete directory '/testdir'");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_delete_dir;
    rc = get_next_completion_entry(&file_server_interface, &rc_delete_dir);
    expect_eq_int(rc, FS_OK, "Get completion for delete dir");
    expect_eq_uint32(rc_delete_dir.return_code, FS_OK, "Delete directory '/testdir'");

    // List files again
    test_begin("List files after deleting '/testdir'");
    rc = send_list_entries_request("/\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue list entries after deleting dir");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_list_after_del_dir;
    rc = get_next_completion_entry(&file_server_interface, &rc_list_after_del_dir);
    expect_eq_int(rc, FS_OK, "Get completion for list after deleting dir");
    expect_eq_uint32(rc_list_after_del_dir.return_code, FS_OK, "List after deleting dir returned OK");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\n\0", 12, "Entry 'testfile.txt' listed", rc_list_after_del_dir.buffer_index);

    // try setting permissions on deleted directory
    test_begin("Set permissions of deleted directory '/testdir' to 0b111");
    rc = send_set_entry_permissions_request("/testdir\0", 0b111, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue set permissions on deleted dir");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_setperm_deleted_dir;
    rc = get_next_completion_entry(&file_server_interface, &rc_setperm_deleted_dir);
    expect_eq_int(rc, FS_OK, "Get completion for set permissions on deleted dir");
    expect_eq_uint32(rc_setperm_deleted_dir.return_code, FS_ERR_NOT_FOUND, "Set permissions on deleted directory");

    // test reading from file in deleted directory
    test_begin("Read from file '/testdir/nestedfile.txt' in deleted directory");
    rc = send_read_file_request(1, sizeof(write_data), &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue read from nested file id 1");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_read_deleted_dir_file;
    rc = get_next_completion_entry(&file_server_interface, &rc_read_deleted_dir_file);
    expect_eq_int(rc, FS_OK, "Get completion for read nested in deleted dir");
    expect_not_eq_int(rc_read_deleted_dir_file.return_code, FS_OK, "Read from file in deleted directory");

    // Check directory doesnt exist
    test_begin("Check '/testdir' does not exist after deletion");
    rc = send_entry_exists_request("/testdir\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue entry exists check");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_exists_dir_deleted;
    rc = get_next_completion_entry(&file_server_interface, &rc_exists_dir_deleted);
    expect_eq_int(rc, FS_OK, "Get completion for exists check");
    expect_eq_uint32(rc_exists_dir_deleted.return_code, FS_OK, "Exists returned OK");
    expect_eq_uint32(rc_exists_dir_deleted.parameter1, 0, "Entry does not exist");

    // List deleted directory contents
    test_begin("List files in deleted directory '/testdir'");
    rc = send_list_entries_request("/testdir\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue list deleted directory");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_list_deleted_dir;
    rc = get_next_completion_entry(&file_server_interface, &rc_list_deleted_dir);
    expect_eq_int(rc, FS_OK, "Get completion for list deleted dir");
    expect_eq_uint32(rc_list_deleted_dir.return_code, FS_ERR_NOT_FOUND, "List entries in deleted directory");

    // seek to start of file again
    test_begin("Seek to start of file '/testfile.txt' again");
    rc = send_seek_file_request(0, 0, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue seek to start again");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_seek_start_again1;
    rc = get_next_completion_entry(&file_server_interface, &rc_seek_start_again1);
    expect_eq_int(rc, FS_OK, "Get completion for seek start again");
    expect_eq_uint32(rc_seek_start_again1.return_code, FS_OK, "Seek to start returned OK");

    //write a lot - make blocks small
    test_begin("Write a lot of data to '/testfile.txt'");
    const unsigned char *lots = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    rc = send_write_file_request(0, 2791, lots, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue large write");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_write_lots0;
    rc = get_next_completion_entry(&file_server_interface, &rc_write_lots0);
    expect_eq_int(rc, FS_OK, "Get completion for large write");
    expect_eq_uint32(rc_write_lots0.return_code, FS_OK, "Large write returned OK");
    expect_eq_uint32(rc_write_lots0.parameter1, 2791, "Bytes written is correct for more data");
    expect_eq_uint32(rc_write_lots0.parameter2, 2791, "Cursor position is correct after more data write");

    // seek to start of file again
    test_begin("Seek to start of file '/testfile.txt' again");
    rc = send_seek_file_request(0, 0, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue seek to start again");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_seek_start_again2;
    rc = get_next_completion_entry(&file_server_interface, &rc_seek_start_again2);
    expect_eq_int(rc, FS_OK, "Get completion for seek start again");
    expect_eq_uint32(rc_seek_start_again2.return_code, FS_OK, "Seek to start returned OK");

    //read a lot - make blocks small
    test_begin("Read full file '/testfile.txt' after large write");
    rc = send_read_file_request(0, rc_write_lots0.parameter2, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue full file read after large write");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_read_lots0;
    rc = get_next_completion_entry(&file_server_interface, &rc_read_lots0);
    expect_eq_int(rc, FS_OK, "Get completion for full file read");
    expect_eq_uint32(rc_read_lots0.return_code, FS_OK, "Read full file returned OK");
    expect_eq_uint32(rc_read_lots0.parameter1, 2791, "Bytes read is correct for full file");
    expect_eq_uint32(rc_read_lots0.parameter2, 2791, "Cursor position is correct for full file");
    expect_equal_to_client_buffer((const unsigned char *)lots, 2791, "Data read matches expected data", rc_read_lots0.buffer_index);

    // Close file
    test_begin("Close file ID 0 ('/testfile.txt')");
    rc = send_close_file_request(0, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue close file 0");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_close_file0;
    rc = get_next_completion_entry(&file_server_interface, &rc_close_file0);
    expect_eq_int(rc, FS_OK, "Get completion for close file 0");
    expect_eq_uint32(rc_close_file0.return_code, FS_OK, "Close file ID 0");

    // Try closing again
    test_begin("Close file ID 0 ('/testfile.txt') again");
    rc = send_close_file_request(0, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue close file again");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_close_file0_again;
    rc = get_next_completion_entry(&file_server_interface, &rc_close_file0_again);
    expect_eq_int(rc, FS_OK, "Get completion for close again");
    expect_eq_uint32(rc_close_file0_again.return_code, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Close file ID 0 again");

    // Try reading closed file
    test_begin("Read from closed file ID 0 ('/testfile.txt')");
    rc = send_read_file_request(0, sizeof(write_data), &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue read from closed file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_read_closed0;
    rc = get_next_completion_entry(&file_server_interface, &rc_read_closed0);
    expect_eq_int(rc, FS_OK, "Get completion for read closed");
    expect_eq_uint32(rc_read_closed0.return_code, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Read from closed file ID 0");

    // Set permissions
    test_begin("Set permissions of '/testfile.txt' to 0b100");
    rc = send_set_entry_permissions_request("/testfile.txt\0", PERM_READ, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue set permissions");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_set_perm_file;
    rc = get_next_completion_entry(&file_server_interface, &rc_set_perm_file);
    expect_eq_int(rc, FS_OK, "Get completion for set permissions");
    expect_eq_uint32(rc_set_perm_file.return_code, FS_OK, "Set permissions returned OK");

    // Get permissions
    test_begin("Get permissions of '/testfile.txt'");
    rc = send_get_entry_permissions_request("/testfile.txt\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue get permissions");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_get_perm_file;
    rc = get_next_completion_entry(&file_server_interface, &rc_get_perm_file);
    expect_eq_int(rc, FS_OK, "Get completion for get permissions");
    expect_eq_uint32(rc_get_perm_file.return_code, FS_OK, "Get permissions returned OK");
    expect_eq_uint32(rc_get_perm_file.parameter1, PERM_READ, "Permissions are 0b100");

    // Reopen file
    test_begin("Reopen file '/testfile.txt'");
    rc = send_open_file_request(READ_OP, "/testfile.txt\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue reopen file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_reopen_file0;
    rc = get_next_completion_entry(&file_server_interface, &rc_reopen_file0);
    expect_eq_int(rc, FS_OK, "Get completion for reopen file");
    expect_eq_uint32(rc_reopen_file0.return_code, FS_OK, "Reopen returned OK");
    expect_eq_uint32(rc_reopen_file0.parameter1, 0, "File ID is 0");

    // Check contents after reopen and seeking to start
    test_begin("Check contents of '/testfile.txt' after reopening");
    rc = send_seek_file_request(0, 0, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue seek to start after reopen");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_seek_after_reopen0;
    rc = get_next_completion_entry(&file_server_interface, &rc_seek_after_reopen0);
    expect_eq_int(rc, FS_OK, "Get completion for seek after reopen");
    expect_eq_uint32(rc_seek_after_reopen0.return_code, FS_OK, "Seek after reopen returned OK");
    rc = send_read_file_request(0, rc_write_lots0.parameter2, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue read from file after reopen");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_read_after_reopen0;
    rc = get_next_completion_entry(&file_server_interface, &rc_read_after_reopen0);
    expect_eq_int(rc, FS_OK, "Get completion for read after reopen");
    expect_eq_uint32(rc_read_after_reopen0.return_code, FS_OK, "Read after reopen returned OK");
    expect_eq_uint32(rc_read_after_reopen0.parameter1, 2791, "Bytes read is correct after reopen");
    expect_eq_uint32(rc_read_after_reopen0.parameter2, 2791, "Cursor position is correct after reopen");
    expect_equal_to_client_buffer((const unsigned char *)lots, 2791, "Data read matches data written after reopen", rc_read_after_reopen0.buffer_index);

    // Check cant write to read-only opened file
    test_begin("Attempt to write to read-only opened file '/testfile.txt'");
    rc = send_write_file_request(0, sizeof(write_data), write_data, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue write to read-only file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_write_readonly0;
    rc = get_next_completion_entry(&file_server_interface, &rc_write_readonly0);
    expect_eq_int(rc, FS_OK, "Get completion for write to read-only");
    expect_eq_uint32(rc_write_readonly0.return_code, FS_ERR_PERMISSION, "Attempt to write to read-only opened file");
    
    // delete non-existent file
    test_begin("Delete non-existent file '/nonexistent.txt'");
    rc = send_delete_entry_request("/nonexistent.txt\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue delete non-existent file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_delete_nonexistent;
    rc = get_next_completion_entry(&file_server_interface, &rc_delete_nonexistent);
    expect_eq_int(rc, FS_OK, "Get completion for delete non-existent");
    expect_eq_uint32(rc_delete_nonexistent.return_code, FS_ERR_NOT_FOUND, "Delete non-existent file");

    // create file with invalid name, \0, /, maxlength
    test_begin("Create file with invalid name '//df'");
    rc = send_create_file_request("//df\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue create with invalid name");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_create_invalid5;
    rc = get_next_completion_entry(&file_server_interface, &rc_create_invalid5);
    expect_eq_int(rc, FS_OK, "Get completion for create invalid //df");
    expect_eq_uint32(rc_create_invalid5.return_code, FS_ERR_INVALID_PATH, "Create file with invalid name");

    test_begin("Create file with invalid name 'd/f'");
    rc = send_create_file_request("d/f\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue create invalid d/f");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_create_invalid6;
    rc = get_next_completion_entry(&file_server_interface, &rc_create_invalid6);
    expect_eq_int(rc, FS_OK, "Get completion for create invalid d/f");
    expect_eq_uint32(rc_create_invalid6.return_code, FS_ERR_INVALID_PATH, "Create file with invalid name");

    test_begin("Create file with invalid name '0'");
    rc = send_create_file_request("\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue create invalid 0 name");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_create_invalid7;
    rc = get_next_completion_entry(&file_server_interface, &rc_create_invalid7);
    expect_eq_int(rc, FS_OK, "Get completion for create invalid 0");
    expect_eq_uint32(rc_create_invalid7.return_code, FS_ERR_INVALID_PATH, "Create file with invalid name");

    test_begin("Create file with invalid name ''");
    rc = send_create_file_request("", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue create invalid empty name");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_create_invalid8;
    rc = get_next_completion_entry(&file_server_interface, &rc_create_invalid8);
    expect_eq_int(rc, FS_OK, "Get completion for create invalid empty");
    expect_eq_uint32(rc_create_invalid8.return_code, FS_ERR_INVALID_PATH, "Create file with invalid name");


    // create directory with invalid name, ''
    test_begin("Create directory with invalid name '//df'");
    rc = send_create_directory_request("//df\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue mkdir //df");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_mkdir_invalid5;
    rc = get_next_completion_entry(&file_server_interface, &rc_mkdir_invalid5);
    expect_eq_int(rc, FS_OK, "Get completion mkdir //df");
    expect_eq_uint32(rc_mkdir_invalid5.return_code, FS_ERR_INVALID_PATH, "Create directory with invalid name");

    test_begin("Create directory with invalid name 'd/f'");
    rc = send_create_directory_request("d/f\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue mkdir d/f");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_mkdir_invalid6;
    rc = get_next_completion_entry(&file_server_interface, &rc_mkdir_invalid6);
    expect_eq_int(rc, FS_OK, "Get completion mkdir d/f");
    expect_eq_uint32(rc_mkdir_invalid6.return_code, FS_ERR_INVALID_PATH, "Create directory with invalid name");
    test_begin("Create directory with invalid name '0'");
    rc = send_create_directory_request("\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue mkdir 0");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_mkdir_invalid7;
    rc = get_next_completion_entry(&file_server_interface, &rc_mkdir_invalid7);
    expect_eq_int(rc, FS_OK, "Get completion mkdir 0");
    expect_eq_uint32(rc_mkdir_invalid7.return_code, FS_ERR_INVALID_PATH, "Create directory with invalid name");
    test_begin("Create directory with invalid name ''");
    rc = send_create_directory_request("", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue mkdir empty name");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_mkdir_invalid8;
    rc = get_next_completion_entry(&file_server_interface, &rc_mkdir_invalid8);
    expect_eq_int(rc, FS_OK, "Get completion mkdir empty");
    expect_eq_uint32(rc_mkdir_invalid8.return_code, FS_ERR_INVALID_PATH, "Create directory with invalid name");

    // delete root
    test_begin("Delete root directory '/'");
    rc = send_delete_entry_request("/\0", &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue delete root");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_del_root;
    rc = get_next_completion_entry(&file_server_interface, &rc_del_root);
    expect_eq_int(rc, FS_OK, "Get completion delete root");
    expect_eq_uint32(rc_del_root.return_code, FS_ERR_PERMISSION, "Delete root directory");

    // create dir with name of file
    test_begin("Create directory with name of existing file '/testfile.txt'");
    rc = send_create_directory_request("/testfile.txt\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue mkdir with file name");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_mkdir_file_name;
    rc = get_next_completion_entry(&file_server_interface, &rc_mkdir_file_name);
    expect_eq_int(rc, FS_OK, "Get completion mkdir with file name");
    expect_eq_uint32(rc_mkdir_file_name.return_code, FS_ERR_ALREADY_EXISTS, "Create directory with name of existing file");

    // write on invalid file id
    test_begin("Write to invalid file ID 99");
    rc = send_write_file_request(99, sizeof(write_data), write_data, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue write to invalid fd");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_write_invalid_fd;
    rc = get_next_completion_entry(&file_server_interface, &rc_write_invalid_fd);
    expect_eq_int(rc, FS_OK, "Get completion write invalid fd");
    expect_eq_uint32(rc_write_invalid_fd.return_code, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Write to invalid file ID");

    // create file with max length name
    test_begin("Create file with maximum length name");
    rc = send_create_file_request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue create max length file name");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_create_maxlen_file;
    rc = get_next_completion_entry(&file_server_interface, &rc_create_maxlen_file);
    expect_eq_int(rc, FS_OK, "Get completion create max len file");
    expect_eq_uint32(rc_create_maxlen_file.return_code, FS_ERR_INVALID_PATH, "Create file with maximum length name");

    // create directory with max length name
    test_begin("Create directory with maximum length name");
    rc = send_create_directory_request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue mkdir max length name");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_mkdir_maxlen_dir;
    rc = get_next_completion_entry(&file_server_interface, &rc_mkdir_maxlen_dir);
    expect_eq_int(rc, FS_OK, "Get completion mkdir max len dir");
    expect_eq_uint32(rc_mkdir_maxlen_dir.return_code, FS_ERR_INVALID_PATH, "Create directory with maximum length name");

    
    //block table full - make block table small
    //add max number of files to dir - make child entries massive
    //max open files - make max open files small
    //i node table full - make i node table small


    // Batched create file write seek and read
    test_begin("Batched write and read to '/testfile.txt'");
    rc = send_create_file_request("/batchedfile.txt\0", READ_WRITE_OP, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue create batched file");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_create_batched;
    rc = get_next_completion_entry(&file_server_interface, &rc_create_batched);
    expect_eq_int(rc, FS_OK, "Get completion for create batched file");
    expect_eq_uint32(rc_create_batched.return_code, FS_OK, "Create batched file returned OK");
    expect_eq_uint32(rc_create_batched.parameter1, 1, "Batched File ID is 1");
    rc = send_write_file_request(1, sizeof(write_data), write_data, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue batched write");
    rc = send_seek_file_request(1, 0, &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue seek to start before batched read");
    rc = send_read_file_request(1, sizeof(write_data), &file_server_interface);
    expect_eq_int(rc, FS_OK, "Queue batched read");
    notify_file_server(&file_server_interface, 1);
    completion_queue_entry_t rc_batched_write;
    rc = get_next_completion_entry(&file_server_interface, &rc_batched_write);
    expect_eq_int(rc, FS_OK, "Get completion for batched write");
    expect_eq_uint32(rc_batched_write.return_code, FS_OK, "Batched write returned OK");
    expect_eq_uint32(rc_batched_write.parameter1, sizeof(write_data), "Bytes written in batched write");
    expect_eq_uint32(rc_batched_write.parameter2, sizeof(write_data), "Cursor position after batched write");
    completion_queue_entry_t rc_batched_seek;
    rc = get_next_completion_entry(&file_server_interface, &rc_batched_seek);
    expect_eq_int(rc, FS_OK, "Get completion for batched seek");
    expect_eq_uint32(rc_batched_seek.return_code, FS_OK, "Batched seek returned OK");
    completion_queue_entry_t rc_batched_read;
    rc = get_next_completion_entry(&file_server_interface, &rc_batched_read);
    expect_eq_int(rc, FS_OK, "Get completion for batched read");
    expect_eq_uint32(rc_batched_read.return_code, FS_OK, "Batched read returned OK");
    expect_eq_uint32(rc_batched_read.parameter1, sizeof(write_data), "Bytes read in batched read");
    expect_eq_uint32(rc_batched_read.parameter2, sizeof(write_data), "Cursor position after batched read");
    expect_equal_to_client_buffer((const unsigned char *)write_data, sizeof(write_data), "Data read matches data written in batched operation", rc_batched_read.buffer_index);

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
    microkit_dbg_puts("initialising submission queue\n");
    file_server_submission_queue = (submission_queue_entry_t *)file_server_submission_queue_base;
    microkit_dbg_puts("initialising completion queue\n");
    file_server_completion_queue = (completion_queue_entry_t *)file_server_completion_queue_base;
    microkit_dbg_puts("initialising sub buffer\n");
    file_server_submission_buffer = (uint8_t *)file_server_submission_buffer_base;
    microkit_dbg_puts("initialising comp buffer\n");
    file_server_completion_buffer = (uint8_t *)file_server_completion_buffer_base;
    microkit_dbg_puts("initialising buffer table\n");
    buffer_table = (uint8_t *)buffer_table_base;
    microkit_dbg_puts("initialising file server interface submission queue\n");
    file_server_interface.file_server_submission_queue = file_server_submission_queue;
    file_server_interface.file_server_completion_queue = file_server_completion_queue;
    file_server_interface.file_server_submission_buffer = file_server_submission_buffer;
    file_server_interface.file_server_completion_buffer = file_server_completion_buffer;
    file_server_interface.buffer_table = buffer_table;
    // print sub tail
    microkit_dbg_puts("Submission queue head is: ");
    microkit_dbg_put32(*SUBMISSION_QUEUE_HEAD(file_server_submission_queue));
    microkit_dbg_putc('\n');
    microkit_dbg_puts("Submission queue tail is: ");
    microkit_dbg_put32(*SUBMISSION_QUEUE_TAIL(file_server_submission_queue));
    microkit_dbg_putc('\n');
    microkit_dbg_puts("Completion queue head is: ");
    microkit_dbg_put32(*COMPLETION_QUEUE_HEAD(file_server_completion_queue));
    microkit_dbg_putc('\n');
    microkit_dbg_puts("Completion queue tail is: ");
    microkit_dbg_put32(*COMPLETION_QUEUE_TAIL(file_server_completion_queue));
    microkit_dbg_putc('\n');
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("TESTING: started\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    run_tests();
}
