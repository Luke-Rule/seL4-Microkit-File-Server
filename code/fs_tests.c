#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include "definitions.h"
#include "utils.c"
#include "file_operations.c"

#define FILE_SERVER_CHANNEL_ID 0
#define MAX_FILE_SIZE 0x100000

uintptr_t file_server_buffer_base;
uint8_t *fs_buffer_base;

void notified(microkit_channel client_id) {}

static int tests_passed = 0;
static int tests_failed = 0;

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
            microkit_dbg_puts((const char *)expected);
            microkit_dbg_puts(", Got: ");
            microkit_dbg_puts((const char *)fs_buffer_base);
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

void run_tests() {
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nStarting filesystem tests...\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    int rc;

    // Test cases 

    // List empty filesystem
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files in empty filesystem\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    rc = send_list_files_request(fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_OK, "List files");
    expect_true(fs_buffer_base[0] == '\0', "List files - empty initially");

    // Create normal file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create normal file\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_fileid_t res_create = send_create_file_request((const unsigned char *)"testfile.txt", 512, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_create.rc, FS_OK, "Create normal file");
    expect_true(res_create.file_id >= 0, "Create normal file - valid file ID");
    
    // List 1 file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files after creating one file\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    rc = send_list_files_request(fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_OK, "List files - after reset");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\0\0", 12, "List files - contains created file");

    // List 2 files
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create second normal file and list files\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_fileid_t res_create2 = send_create_file_request((const unsigned char *)"secondfile.txt", 256, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_create2.rc, FS_OK, "Create second normal file");
    rc = send_list_files_request(fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_OK, "List files - after creating second file");
    expect_equal_to_client_buffer((const unsigned char *)"testfile.txt\0secondfile.txt\0\0", 12, "List files - contains created files");

    // Create duplicate name
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file with duplicate name\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_fileid_t res_create_dup = send_create_file_request((const unsigned char *)"testfile.txt", 256, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_create_dup.rc, FS_ERR_ALREADY_EXISTS, "Create duplicate name");
    
    // Create invalid name
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file with invalid name\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_fileid_t res_create_invalid = send_create_file_request((const unsigned char *)"", 256, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_create_invalid.rc, FS_ERR_INVALID_NAME, "Create invalid name");
    
    // Create file exceeding MAX_FILE_SIZE
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file exceeding MAX_FILE_SIZE\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_fileid_t res_create_exceed_max = send_create_file_request((const unsigned char *)"largefile.txt", MAX_FILE_SIZE + 1, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_create_exceed_max.rc, FS_ERR_FILE_EXCEEDS_MAX_SIZE, "Create file exceeding MAX_FILE_SIZE");
    
    // Create file exceeding remaining space
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Create file exceeding remaining space\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_fileid_t res_create_exceed_space = send_create_file_request((const unsigned char *)"hugefile.txt", MAX_FILE_SIZE - 1, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_create_exceed_space.rc, FS_ERR_FILE_EXCEEDS_REMAINING_SPACE, "Create file exceeding remaining space");
    
    // Open existing file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Open existing file\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_fileid_t res_open = send_open_file_request((const unsigned char *)"testfile.txt", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_open.rc, FS_OK, "Open existing file");
    expect_eq_uint32(res_open.file_id, (uint32_t)res_create.file_id, "Open existing file - correct ID");

    // Open non-existent file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Open non-existent file\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_fileid_t res_open_nonexistent = send_open_file_request((const unsigned char *)"nonexistent.txt", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_open_nonexistent.rc, FS_ERR_NOT_FOUND, "Open non-existent file");

    // Write and read in-bounds as owner
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Write and read in-bounds as owner\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    rc = send_write_file_request((uint32_t)res_open.file_id, 0, 13, (uint8_t *)"Hello, World!", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_OK, "Write in-bounds as owner");
    rc = send_read_file_request((uint32_t)res_open.file_id, 0, 13, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_OK, "Read in-bounds as owner");
    expect_equal_to_client_buffer((const unsigned char *)"Hello, World!", 13, "Read in-bounds as owner - correct data");

    // Read out-of-bounds
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Read out-of-bounds\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    rc = send_read_file_request((uint32_t)res_open.file_id, 600, 20, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_ERR_OUT_OF_BOUNDS, "Read out-of-bounds");

    // Write out-of-bounds
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Write out-of-bounds\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    int res_write_oob = send_write_file_request((uint32_t)res_open.file_id, 600, 20, (uint8_t *)"Hello, World!", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_write_oob, FS_ERR_OUT_OF_BOUNDS, "Write out-of-bounds");

    // Delete 
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Delete file as owner\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    int res_delete = send_delete_file_request((uint32_t)res_open.file_id, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_delete, FS_OK, "Delete as owner");
    fs_result_fileid_t res_open_deleted = send_open_file_request((const unsigned char *)"testfile.txt", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_open_deleted.rc, FS_ERR_NOT_FOUND, "Open deleted file");

    // List files after deletion
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: List files after deletion\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    rc = send_list_files_request(fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_OK, "List files - after deletion");
    expect_equal_to_client_buffer((const unsigned char *)"secondfile.txt\0\0", 16, "List files - contains remaining file after deletion");

    // Set and get permissions as owner
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Set and get permissions as owner\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    rc = send_set_file_permissions_request((uint32_t)res_create2.file_id, FILE_PERM_PUBLIC_WRITE_AND_DELETE_AND_RENAME, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_OK, "Set permissions as owner");
    fs_result_permissions_t res_get_perm = send_get_file_permissions_request((uint32_t)res_create2.file_id, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_get_perm.rc, FS_OK, "Get permissions as owner");
    expect_eq_uint32((uint32_t)res_get_perm.permissions, (uint32_t)FILE_PERM_PUBLIC_WRITE_AND_DELETE_AND_RENAME, "Get permissions as owner - correct value");

    // Rename file to new unique name
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Rename file to new unique name\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    rc = send_rename_file_request((uint32_t)res_create2.file_id, (const unsigned char *)"renamedfile.txt", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_OK, "Rename file to new unique name");
    rc = send_list_files_request(fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_OK, "List files - after rename");
    expect_equal_to_client_buffer((const unsigned char *)"renamedfile.txt\0\0", 17, "List files - contains renamed file");

    // Rename file to existing name
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Rename file to existing name\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    rc = send_rename_file_request((uint32_t)res_create2.file_id, (const unsigned char *)"renamedfile.txt", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_ERR_ALREADY_EXISTS, "Rename file to existing name");

    // Rename non-existent file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Rename non-existent file\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    rc = send_rename_file_request(9999, (const unsigned char *)"nonexistent.txt", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_ERR_NOT_FOUND, "Rename non-existent file");

    // Get file size
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Get file size\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_size_t res_get_size = send_get_file_size_request((uint32_t)res_create2.file_id, fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_uint32(res_get_size.rc, FS_OK, "Get file size");
    expect_eq_uint32(res_get_size.size, 256, "Get file size");

    // File exists
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Check file existence\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_exists_t res_exists = send_file_exists_request((const unsigned char *)"renamedfile.txt", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_exists.rc, FS_OK, "File exists - public file");
    expect_true(res_exists.exists, "File exists - public file exists");

    // File does not exist
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Check non-existent file existence\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_exists_t res_not_exists = send_file_exists_request((const unsigned char *)"nonexistent.txt", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_not_exists.rc, FS_OK, "File exists - non-existent file");
    expect_true(!res_not_exists.exists, "File exists - non-existent file does not exist");

    // Copy file
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n\nTest: Copy file\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    fs_result_fileid_t res_copy = send_copy_file_request((uint32_t)res_create2.file_id, (const unsigned char *)"copy_of_renamedfile.txt", fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(res_copy.rc, FS_OK, "Copy file");
    expect_true(res_copy.file_id != res_create2.file_id, "Copy file - distinct file ID");
    rc = send_list_files_request(fs_buffer_base, FILE_SERVER_CHANNEL_ID);
    expect_eq_int(rc, FS_OK, "List files - after copy");
    expect_equal_to_client_buffer((const unsigned char *)"renamedfile.txt\0copy_of_renamedfile.txt\0\0", 41, "List files - contains copied file");


    // Permissions tests ...

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
