// ----------------------------------------------------------------------- //
// --------------------- MicroKit File Server Tests ---------------------- //
// ----------------------------------------------------------------------- //


// ------------------------------ Includes ------------------------------- //

#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../../../debug_output.h"

#include "../../fs/include/fs_api.h"
#include "../include/test_utils.h"

// ------------------------------- Globals --------------------------------- //

uintptr_t fs_data_base;
client_t *client_data;
int tests_passed = 0;
int tests_failed = 0;

// ------------------------------- Independent tests --------------------------------- //

static bool test_completion_queue_starts_empty(void) {
    completion_queue_entry_t empty;
    fs_result_t rc = get_next_completion_entry(client_data, &empty);
    if (!expect_eq_int(rc, FS_ERROR_NO_COMPLETION_ENTRIES_AVAILABLE, "No completion entries available initially")) {
        return false;
    }
    return true;
}

static bool test_list_empty_directory(void) {
    if (!ensure_clean_test_root(client_data)) {
        return false;
    }

    fs_result_t rc = send_list_entries_request("/__tests", client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue list /__tests")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c;
    if (!get_completion(&c, "List /__tests", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c.return_code, FS_OK, "List empty directory returned OK")) {
        return false;
    }
    if (!expect_equal_to_client_buffer((const unsigned char *)"\0", 1, "Empty directory lists nothing", c.buffer_index, client_data)) {
        return false;
    }

    return true;
}

static bool test_create_write_read_roundtrip(void) {
    if (!ensure_clean_test_root(client_data)) {
        return false;
    }

    const unsigned char path[] = "/__tests/a.txt";
    const unsigned char data[] = "Hello, seL4 File Server!";

    fs_result_t rc = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create a.txt")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_create;
    if (!get_completion(&c_create, "Create a.txt", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_create.return_code, FS_OK, "Create file returned OK")) {
        return false;
    }
    uint32_t fd = c_create.parameter1;

    test_begin((char *)"Write zero bytes then read zero bytes (cursor should not move)");
    rc = send_write_file_request(fd, 0, (const uint8_t *)"x", client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue write 0 bytes")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_w0;
    if (!get_completion(&c_w0, "Write 0 bytes", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_w0.return_code, FS_OK, "Write 0 bytes returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_w0.parameter1, 0, "Bytes written is 0")) {
        return false;
    }
    if (!expect_eq_uint32(c_w0.parameter2, 0, "Cursor unchanged after write 0")) {
        return false;
    }

    rc = send_read_file_request(fd, 0, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue read 0 bytes")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_r0;
    if (!get_completion(&c_r0, "Read 0 bytes", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_r0.return_code, FS_OK, "Read 0 bytes returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_r0.parameter1, 0, "Bytes read is 0")) {
        return false;
    }
    if (!expect_eq_uint32(c_r0.parameter2, 0, "Cursor unchanged after read 0")) {
        return false;
    }

    output_pass((unsigned char *)"Write zero bytes then read zero bytes (cursor should not move)");

    test_begin((char *)"Write then read back");
    rc = send_write_file_request(fd, sizeof(data), data, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue write data")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_w;
    if (!get_completion(&c_w, "Write data", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_w.return_code, FS_OK, "Write returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_w.parameter1, sizeof(data), "Bytes written equals data length")) {
        return false;
    }

    rc = send_seek_file_request(fd, 0, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue seek 0")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_s;
    if (!get_completion(&c_s, "Seek 0", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_s.return_code, FS_OK, "Seek returned OK")) {
        return false;
    }

    rc = send_read_file_request(fd, sizeof(data), client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue read back")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_r;
    if (!get_completion(&c_r, "Read back", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_r.return_code, FS_OK, "Read returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_r.parameter1, sizeof(data), "Bytes read equals data length")) {
        return false;
    }
    if (!expect_equal_to_client_buffer(data, sizeof(data), "Readback matches write", c_r.buffer_index, client_data)) {
        return false;
    }

    rc = send_close_file_request(fd, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue close")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_close;
    if (!get_completion(&c_close, "Close", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_close.return_code, FS_OK, "Close returned OK")) {
        return false;
    }

    output_pass((unsigned char *)"Write then read back");

    return true;
}

static bool test_duplicate_create_fails(void) {
    if (!ensure_clean_test_root(client_data)) {
        return false;
    }
    const unsigned char path[] = "/__tests/dup.txt";

    fs_result_t rc = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create dup.txt")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c1;
    if (!get_completion(&c1, "Create dup.txt", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c1.return_code, FS_OK, "Create dup.txt returned OK")) {
        return false;
    }

    rc = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create duplicate")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c2;
    if (!get_completion(&c2, "Create duplicate", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c2.return_code, FS_ERR_ALREADY_EXISTS, "Duplicate create fails with already exists")) {
        return false;
    }

    return true;
}

static bool test_directory_file_conflicts(void) {
    if (!ensure_clean_test_root(client_data)) {
        return false;
    }

    test_begin((char *)"Create a directory and ensure you cannot open it as a file");
    fs_result_t rc = send_create_directory_request("/__tests/subdir", READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue mkdir subdir")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_mkdir;
    if (!get_completion(&c_mkdir, "Mkdir subdir", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_mkdir.return_code, FS_OK, "Create directory returned OK")) {
        return false;
    }

    if (!fs_test_open_expect_rc(READ_OP, (const unsigned char *)"/__tests/subdir", FS_ERR_INVALID_PATH, "Open dir as file", client_data)) {
        return false;
    }

    output_pass((unsigned char *)"Create a directory and ensure you cannot open it as a file");

    test_begin((char *)"Cannot create a file with same name as existing directory");
    rc = send_create_file_request("/__tests/subdir", PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create file named subdir")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_cf;
    if (!get_completion(&c_cf, "Create file named subdir", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_cf.return_code, FS_ERR_ALREADY_EXISTS, "File named like existing directory fails")) {
        return false;
    }

    output_pass((unsigned char *)"Cannot create a file with same name as existing directory");

    test_begin((char *)"Create a file and ensure you cannot create directory with same name");
    rc = send_create_file_request("/__tests/a.txt", PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create a.txt")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_file;
    if (!get_completion(&c_file, "Create a.txt", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_file.return_code, FS_OK, "Create file returned OK")) {
        return false;
    }

    rc = send_create_directory_request("/__tests/a.txt", READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue mkdir with file name")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_mkdir2;
    if (!get_completion(&c_mkdir2, "Mkdir with file name", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_mkdir2.return_code, FS_ERR_ALREADY_EXISTS, "Directory named like existing file fails")) {
        return false;
    }

    output_pass((unsigned char *)"Create a file and ensure you cannot create directory with same name");

    return true;
}

static bool test_nested_directory_listing_and_size(void) {
    if (!ensure_clean_test_root(client_data)) {
        return false;
    }

    const unsigned char dir_path[] = "/__tests/subdir";
    const unsigned char file_path[] = "/__tests/subdir/nestedfile.txt";
    const unsigned char payload[] = "Nested file data.";

    fs_result_t rc = send_create_directory_request(dir_path, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue mkdir subdir")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_mkdir;
    if (!get_completion(&c_mkdir, "Mkdir subdir", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_mkdir.return_code, FS_OK, "Mkdir returned OK")) {
        return false;
    }

    rc = send_list_entries_request(dir_path, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue list empty subdir")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_list_empty;
    if (!get_completion(&c_list_empty, "List empty subdir", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_list_empty.return_code, FS_OK, "List empty subdir returned OK")) {
        return false;
    }
    if (!expect_equal_to_client_buffer((const unsigned char *)"\0", 1, "Empty subdir lists nothing", c_list_empty.buffer_index, client_data)) {
        return false;
    }

    rc = send_create_file_request(file_path, PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create nested file")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_create;
    if (!get_completion(&c_create, "Create nested file", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_create.return_code, FS_OK, "Create nested file returned OK")) {
        return false;
    }
    uint32_t fd = c_create.parameter1;

    rc = send_write_file_request(fd, sizeof(payload), payload, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue write nested")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_write;
    if (!get_completion(&c_write, "Write nested", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_write.return_code, FS_OK, "Write nested returned OK")) {
        return false;
    }

    rc = send_seek_file_request(fd, 0, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue seek nested 0")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_seek;
    if (!get_completion(&c_seek, "Seek nested 0", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_seek.return_code, FS_OK, "Seek nested returned OK")) {
        return false;
    }

    rc = send_read_file_request(fd, sizeof(payload), client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue read nested")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_read;
    if (!get_completion(&c_read, "Read nested", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_read.return_code, FS_OK, "Read nested returned OK")) {
        return false;
    }
    if (!expect_equal_to_client_buffer(payload, sizeof(payload), "Nested readback matches write", c_read.buffer_index, client_data)) {
        return false;
    }

    rc = send_list_entries_request(dir_path, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue list subdir")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_list1;
    if (!get_completion(&c_list1, "List subdir", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_list1.return_code, FS_OK, "List subdir returned OK")) {
        return false;
    }
    if (!expect_equal_to_client_buffer((const unsigned char *)"nestedfile.txt\n\0", 16, "Subdir lists nested file", c_list1.buffer_index, client_data)) {
        return false;
    }

    test_begin((char *)"Delete nested file and confirm empty");
    rc = send_delete_entry_request(file_path, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue delete nested file")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_del;
    if (!get_completion(&c_del, "Delete nested file", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_del.return_code, FS_OK, "Delete nested file returned OK")) {
        return false;
    }

    rc = send_list_entries_request(dir_path, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue list subdir after delete")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_list2;
    if (!get_completion(&c_list2, "List subdir after delete", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_list2.return_code, FS_OK, "List subdir after delete returned OK")) {
        return false;
    }
    if (!expect_equal_to_client_buffer((const unsigned char *)"\0", 1, "Subdir empty after delete", c_list2.buffer_index, client_data)) {
        return false;
    }

    output_pass((unsigned char *)"Delete nested file and confirm empty");

    test_begin((char *)"Size reflects number of entries");
    rc = send_get_entry_size_request(dir_path, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue size subdir")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_size0;
    if (!get_completion(&c_size0, "Size subdir", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_size0.return_code, FS_OK, "Size subdir returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_size0.parameter1, 0, "Directory size is 0 after delete")) {
        return false;
    }

    rc = send_create_file_request(file_path, PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue re-create nested")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_recreate;
    if (!get_completion(&c_recreate, "Re-create nested", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_recreate.return_code, FS_OK, "Recreate nested returned OK")) {
        return false;
    }

    rc = send_entry_exists_request(file_path, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue exists nested")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_exists;
    if (!get_completion(&c_exists, "Exists nested", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_exists.return_code, FS_OK, "Exists returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_exists.parameter1, 1, "Nested file exists")) {
        return false;
    }

    rc = send_get_entry_size_request(dir_path, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue size subdir after recreate")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_size1;
    if (!get_completion(&c_size1, "Size subdir after recreate", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_size1.return_code, FS_OK, "Size subdir returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_size1.parameter1, 1, "Directory size is 1 after recreate")) {
        return false;
    }

    output_pass((unsigned char *)"Size reflects number of entries");

    return true;
}

static bool test_seek_overwrite_and_oob(void) {
    if (!ensure_clean_test_root(client_data)) {
        return false;
    }

    const unsigned char path[] = "/__tests/seek.txt";
    const unsigned char write_data[] = "Hello, seL4 File Server!";
    const unsigned char more_write_data[] = "wonderful world!";
    const unsigned char expected_full[] = "Hello, wonderful world!";

    fs_result_t rc = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create seek.txt")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_create;
    if (!get_completion(&c_create, "Create seek.txt", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_create.return_code, FS_OK, "Create seek.txt returned OK")) {
        return false;
    }
    uint32_t fd = c_create.parameter1;

    rc = send_write_file_request(fd, sizeof(write_data), write_data, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue write initial")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_write;
    if (!get_completion(&c_write, "Write initial", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_write.return_code, FS_OK, "Write initial returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_write.parameter1, sizeof(write_data), "Bytes written initial")) {
        return false;
    }

    rc = send_get_entry_size_request(path, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue size seek.txt")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_size;
    if (!get_completion(&c_size, "Size seek.txt", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_size.return_code, FS_OK, "Size returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_size.parameter1, sizeof(write_data), "Size matches write length")) {
        return false;
    }

    test_begin((char *)"Cursor at end after write; reading should be out-of-bounds");
    rc = send_read_file_request(fd, sizeof(write_data), client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue read at end")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_read_end;
    if (!get_completion(&c_read_end, "Read at end", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_read_end.return_code, FS_ERR_OUT_OF_BOUNDS, "Read at end returns OOB")) {
        return false;
    }
    if (!expect_eq_uint32(c_read_end.parameter1, 0, "Bytes read at end is 0")) {
        return false;
    }

    rc = send_seek_file_request(fd, 1000000, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue seek beyond end")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_seek_oob;
    if (!get_completion(&c_seek_oob, "Seek beyond end", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_seek_oob.return_code, FS_ERR_OUT_OF_BOUNDS, "Seek beyond end fails")) {
        return false;
    }

    rc = send_seek_file_request(fd, 0, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue seek 0")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_seek0;
    if (!get_completion(&c_seek0, "Seek 0", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_seek0.return_code, FS_OK, "Seek 0 returned OK")) {
        return false;
    }

    rc = send_read_file_request(fd, sizeof(write_data), client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue read initial back")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_read0;
    if (!get_completion(&c_read0, "Read initial back", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_read0.return_code, FS_OK, "Read initial back returned OK")) {
        return false;
    }
    if (!expect_equal_to_client_buffer(write_data, sizeof(write_data), "Initial readback matches", c_read0.buffer_index, client_data)) {
        return false;
    }

    rc = send_seek_file_request(fd, 7, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue seek middle")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_seek_mid;
    if (!get_completion(&c_seek_mid, "Seek middle", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_seek_mid.return_code, FS_OK, "Seek middle returned OK")) {
        return false;
    }

    rc = send_write_file_request(fd, sizeof(more_write_data), more_write_data, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue overwrite")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_over;
    if (!get_completion(&c_over, "Overwrite", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_over.return_code, FS_OK, "Overwrite returned OK")) {
        return false;
    }

    rc = send_seek_file_request(fd, 0, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue seek 0 again")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_seek1;
    if (!get_completion(&c_seek1, "Seek 0 again", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_seek1.return_code, FS_OK, "Seek returned OK")) {
        return false;
    }

    rc = send_read_file_request(fd, sizeof(expected_full), client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue read full expected")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_full;
    if (!get_completion(&c_full, "Read full expected", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_full.return_code, FS_OK, "Read full returned OK")) {
        return false;
    }
    if (!expect_equal_to_client_buffer(expected_full, sizeof(expected_full), "Overwritten content matches", c_full.buffer_index, client_data)) {
        return false;
    }

    rc = send_close_file_request(fd, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue close seek.txt")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_close;
    if (!get_completion(&c_close, "Close seek.txt", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_close.return_code, FS_OK, "Close returned OK")) {
        return false;
    }

    output_pass((unsigned char *)"Cursor at end after write; reading should be out-of-bounds");

    return true;
}

static bool test_large_write_read(void) {
    if (!ensure_clean_test_root(client_data)) {
        return false;
    }

    const unsigned char path[] = "/__tests/large.txt";
    // Intentionally large constant; we write/read a fixed prefix length.
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

    fs_result_t rc = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create large.txt")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_create;
    if (!get_completion(&c_create, "Create large.txt", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_create.return_code, FS_OK, "Create large.txt returned OK")) {
        return false;
    }
    uint32_t fd = c_create.parameter1;

    rc = send_write_file_request(fd, lots_len, (const uint8_t *)lots, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue large write")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_write;
    if (!get_completion(&c_write, "Large write", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_write.return_code, FS_OK, "Large write returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_write.parameter1, lots_len, "Large write bytes")) {
        return false;
    }

    rc = send_seek_file_request(fd, 0, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue seek 0 large")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_seek;
    if (!get_completion(&c_seek, "Seek 0 large", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_seek.return_code, FS_OK, "Seek returned OK")) {
        return false;
    }

    rc = send_read_file_request(fd, lots_len, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue large read")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_read;
    if (!get_completion(&c_read, "Large read", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_read.return_code, FS_OK, "Large read returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_read.parameter1, lots_len, "Large read bytes")) {
        return false;
    }
    if (!expect_equal_to_client_buffer(lots, lots_len, "Large readback matches write", c_read.buffer_index, client_data)) {
        return false;
    }

    rc = send_close_file_request(fd, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue close large")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_close;
    if (!get_completion(&c_close, "Close large", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_close.return_code, FS_OK, "Close returned OK")) {
        return false;
    }

    return true;
}

static bool test_close_fd_errors_and_permissions(void) {
    if (!ensure_clean_test_root(client_data)) {
        return false;
    }

    const unsigned char path[] = "/__tests/perm.txt";
    const unsigned char payload[] = "Permission test";

    fs_result_t rc = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create perm.txt")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_create;
    if (!get_completion(&c_create, "Create perm.txt", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_create.return_code, FS_OK, "Create perm.txt returned OK")) {
        return false;
    }
    uint32_t fd = c_create.parameter1;

    rc = send_write_file_request(fd, sizeof(payload), payload, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue write perm payload")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_write;
    if (!get_completion(&c_write, "Write perm payload", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_write.return_code, FS_OK, "Write payload returned OK")) {
        return false;
    }

    rc = send_close_file_request(fd, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue close perm fd")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_close;
    if (!get_completion(&c_close, "Close perm fd", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_close.return_code, FS_OK, "Close returned OK")) {
        return false;
    }

    test_begin((char *)"Closing again should fail");
    rc = send_close_file_request(fd, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue close again")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_close2;
    if (!get_completion(&c_close2, "Close again", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_close2.return_code, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Close again fails with FD not found")) {
        return false;
    }

    output_pass((unsigned char *)"Closing again should fail");

    test_begin((char *)"Reading with closed descriptor should fail");
    rc = send_read_file_request(fd, sizeof(payload), client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue read closed")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_read_closed;
    if (!get_completion(&c_read_closed, "Read closed", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_read_closed.return_code, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Read closed fails with FD not found")) {
        return false;
    }

    output_pass((unsigned char *)"Reading with closed descriptor should fail");

    test_begin((char *)"Set/get permissions on path");
    if (!fs_test_set_perm_expect_rc(path, PERM_READ, FS_OK, "Set perm", client_data)) {
        return false;
    }

    rc = send_get_entry_permissions_request(path, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue get perm")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_getp;
    if (!get_completion(&c_getp, "Get perm", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_getp.return_code, FS_OK, "Get perm returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_getp.parameter1, PERM_READ, "Permissions are read-only")) {
        return false;
    }

    output_pass((unsigned char *)"Set/get permissions on path");

    test_begin((char *)"Reopen read-only and verify you can't write, but can read what was written");
    rc = send_open_file_request(path, READ_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue open read-only")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_open;
    if (!get_completion(&c_open, "Open read-only", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_open.return_code, FS_OK, "Open read-only returned OK")) {
        return false;
    }
    uint32_t fd_ro = c_open.parameter1;

    rc = send_seek_file_request(fd_ro, 0, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue seek 0 read-only")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_seek;
    if (!get_completion(&c_seek, "Seek 0 read-only", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_seek.return_code, FS_OK, "Seek returned OK")) {
        return false;
    }

    rc = send_read_file_request(fd_ro, sizeof(payload), client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue read read-only")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_read;
    if (!get_completion(&c_read, "Read read-only", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_read.return_code, FS_OK, "Read returned OK")) {
        return false;
    }
    if (!expect_equal_to_client_buffer(payload, sizeof(payload), "Read-only descriptor reads correct data", c_read.buffer_index, client_data)) {
        return false;
    }

    rc = send_write_file_request(fd_ro, sizeof(payload), payload, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue write read-only")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_wro;
    if (!get_completion(&c_wro, "Write read-only", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_wro.return_code, FS_ERR_PERMISSION, "Write on read-only descriptor fails")) {
        return false;
    }

    rc = send_close_file_request(fd_ro, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue close read-only fd")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_close_ro;
    if (!get_completion(&c_close_ro, "Close read-only fd", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_close_ro.return_code, FS_OK, "Close read-only fd returned OK")) {
        return false;
    }

    output_pass((unsigned char *)"Reopen read-only and verify you can't write, but can read what was written");

    return true;
}

static bool test_deleted_directory_operations_fail(void) {
    if (!ensure_clean_test_root(client_data)) {
        return false;
    }

    test_begin((char *)"Create deldir + nested file, keep FD around");
    fs_result_t rc = send_create_directory_request("/__tests/deldir", READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue mkdir deldir")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_mkdir;
    if (!get_completion(&c_mkdir, "Mkdir deldir", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_mkdir.return_code, FS_OK, "Mkdir deldir returned OK")) {
        return false;
    }

    rc = send_create_file_request("/__tests/deldir/nestedfile.txt", PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create nested in deldir")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_create;
    if (!get_completion(&c_create, "Create nested in deldir", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_create.return_code, FS_OK, "Create nested returned OK")) {
        return false;
    }
    uint32_t fd = c_create.parameter1;

    output_pass((unsigned char *)"Create deldir + nested file, keep FD around");

    test_begin((char *)"Delete directory (implementation is expected to remove contained entry too)");
    rc = send_delete_entry_request("/__tests/deldir", client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue delete deldir")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_del;
    if (!get_completion(&c_del, "Delete deldir", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_del.return_code, FS_OK, "Delete deldir returned OK")) {
        return false;
    }

    output_pass((unsigned char *)"Delete directory (implementation is expected to remove contained entry too)");

    test_begin((char *)"Setting permissions on deleted directory should fail");
    if (!fs_test_set_perm_expect_rc((const unsigned char *)"/__tests/deldir", PERM_PUBLIC, FS_ERR_NOT_FOUND, "Set perms on deleted deldir", client_data)) {
        return false;
    }

    output_pass((unsigned char *)"Setting permissions on deleted directory should fail");

    test_begin((char *)"Reads on the stale FD should not succeed");
    rc = send_read_file_request(fd, 1, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue read stale fd")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_read;
    if (!get_completion(&c_read, "Read stale fd", client_data)) {
        return false;
    }
    if (!expect_true(c_read.return_code != FS_OK, "Read from file in deleted directory should fail")) {
        return false;
    }

    output_pass((unsigned char *)"Reads on the stale FD should not succeed");

    test_begin((char *)"Exists should report not present");
    rc = send_entry_exists_request("/__tests/deldir", client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue exists deldir")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_exists;
    if (!get_completion(&c_exists, "Exists deldir", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_exists.return_code, FS_OK, "Exists deldir returned OK")) {
        return false;
    }
    if (!expect_eq_uint32(c_exists.parameter1, 0, "Deleted directory does not exist")) {
        return false;
    }

    output_pass((unsigned char *)"Exists should report not present");

    test_begin((char *)"List should return not found");
    rc = send_list_entries_request("/__tests/deldir", client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue list deleted deldir")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_list;
    if (!get_completion(&c_list, "List deleted deldir", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_list.return_code, FS_ERR_NOT_FOUND, "List deleted directory returns NOT_FOUND")) {
        return false;
    }

    output_pass((unsigned char *)"List should return not found");

    return true;
}

static bool test_invalid_inputs_and_edge_cases(void) {
    if (!ensure_clean_test_root(client_data)) {
        return false;
    }

    test_begin((char *)"Delete non-existent entry");
    fs_result_t rc;
    if (!fs_test_delete_expect_rc((const unsigned char *)"/__tests/nope.txt", FS_ERR_NOT_FOUND, "Delete non-existent", client_data)) {
        return false;
    }

    output_pass((unsigned char *)"Delete non-existent entry");

    test_begin((char *)"Invalid names: trailing slash gives an empty final component");
    rc = send_create_file_request("/__tests/", PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create invalid /__tests/")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_inv1;
    if (!get_completion(&c_inv1, "Create invalid /__tests/", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_inv1.return_code, FS_ERR_INVALID_PATH, "Create invalid /__tests/ fails")) {
        return false;
    }

    rc = send_create_file_request("d/f", PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create invalid d/f")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_inv2;
    if (!get_completion(&c_inv2, "Create invalid d/f", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_inv2.return_code, FS_ERR_INVALID_PATH, "Create invalid d/f fails")) {
        return false;
    }

    rc = send_create_file_request("\0", PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create invalid NUL")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_inv3;
    if (!get_completion(&c_inv3, "Create invalid NUL", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_inv3.return_code, FS_ERR_INVALID_PATH, "Create invalid NUL fails")) {
        return false;
    }

    rc = send_create_file_request("", PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create invalid empty")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_inv4;
    if (!get_completion(&c_inv4, "Create invalid empty", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_inv4.return_code, FS_ERR_INVALID_PATH, "Create invalid empty fails")) {
        return false;
    }

    rc = send_create_directory_request("/__tests/", READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue mkdir invalid /__tests/")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_m1;
    if (!get_completion(&c_m1, "Mkdir invalid /__tests/", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_m1.return_code, FS_ERR_INVALID_PATH, "Mkdir invalid /__tests/ fails")) {
        return false;
    }

    rc = send_create_directory_request("d/f", READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue mkdir invalid d/f")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_m2;
    if (!get_completion(&c_m2, "Mkdir invalid d/f", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_m2.return_code, FS_ERR_INVALID_PATH, "Mkdir invalid d/f fails")) {
        return false;
    }

    rc = send_create_directory_request("\0", READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue mkdir invalid NUL")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_m3;
    if (!get_completion(&c_m3, "Mkdir invalid NUL", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_m3.return_code, FS_ERR_INVALID_PATH, "Mkdir invalid NUL fails")) {
        return false;
    }

    rc = send_create_directory_request("", READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue mkdir invalid empty")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_m4;
    if (!get_completion(&c_m4, "Mkdir invalid empty", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_m4.return_code, FS_ERR_INVALID_PATH, "Mkdir invalid empty fails")) {
        return false;
    }

    output_pass((unsigned char *)"Invalid names: trailing slash gives an empty final component");

    test_begin((char *)"Root deletion forbidden");
    if (!fs_test_delete_expect_rc((const unsigned char *)"/", FS_ERR_PERMISSION, "Delete root", client_data)) {
        return false;
    }

    output_pass((unsigned char *)"Root deletion forbidden");

    test_begin((char *)"Invalid FD");
    rc = send_write_file_request(99, 1, (const uint8_t *)"x", client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue write invalid fd")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_fd;
    if (!get_completion(&c_fd, "Write invalid fd", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_fd.return_code, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "Write invalid fd fails")) {
        return false;
    }

    output_pass((unsigned char *)"Invalid FD");

    test_begin((char *)"Max-length name should be invalid");
    rc = send_create_file_request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create maxlen file")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_ml1;
    if (!get_completion(&c_ml1, "Create maxlen file", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_ml1.return_code, FS_ERR_INVALID_PATH, "Create maxlen file invalid")) {
        return false;
    }

    rc = send_create_directory_request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue mkdir maxlen")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_ml2;
    if (!get_completion(&c_ml2, "Mkdir maxlen", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_ml2.return_code, FS_ERR_INVALID_PATH, "Mkdir maxlen invalid")) {
        return false;
    }

    output_pass((unsigned char *)"Max-length name should be invalid");

    return true;
}

static bool test_batched_operations_roundtrip(void) {
    if (!ensure_clean_test_root(client_data)) {
        return false;
    }

    const unsigned char path[] = "/__tests/batch.txt";
    const unsigned char payload[] = "Hello, seL4 File Server!";

    fs_result_t rc = send_create_file_request(path, PERM_PRIVATE, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create batch.txt")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_create;
    if (!get_completion(&c_create, "Create batch.txt", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_create.return_code, FS_OK, "Create batch.txt returned OK")) {
        return false;
    }
    uint32_t fd = c_create.parameter1;

    test_begin((char *)"Queue write + seek + read before notifying");
    rc = send_write_file_request(fd, sizeof(payload), payload, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue batched write")) {
        return false;
    }
    rc = send_seek_file_request(fd, 0, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue batched seek")) {
        return false;
    }
    rc = send_read_file_request(fd, sizeof(payload), client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue batched read")) {
        return false;
    }

    notify_file_server_and_wait_for_all_operations(client_data, 3);
    completion_queue_entry_t c_w;
    if (!get_completion(&c_w, "Batched write", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_w.return_code, FS_OK, "Batched write returned OK")) {
        return false;
    }
    completion_queue_entry_t c_s;
    if (!get_completion(&c_s, "Batched seek", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_s.return_code, FS_OK, "Batched seek returned OK")) {
        return false;
    }
    completion_queue_entry_t c_r;
    if (!get_completion(&c_r, "Batched read", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_r.return_code, FS_OK, "Batched read returned OK")) {
        return false;
    }
    if (!expect_equal_to_client_buffer(payload, sizeof(payload), "Batched readback matches write", c_r.buffer_index, client_data)) {
        return false;
    }

    rc = send_close_file_request(fd, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue close batch fd")) {
        return false;
    }
    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c_close;
    if (!get_completion(&c_close, "Close batch fd", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_close.return_code, FS_OK, "Close returned OK")) {
        return false;
    }

    output_pass((unsigned char *)"Queue write + seek + read before notifying");

    return true;
}

// ------------------------------- Test cases --------------------------------- //

void run_tests() {
    microkit_debug_puts(OUTPUT_VERBOSITY, ANSI_COLOR_YELLOW);
    microkit_debug_puts(OUTPUT_VERBOSITY, "\n\nStarting filesystem tests...\n");
    microkit_debug_puts(OUTPUT_VERBOSITY, ANSI_COLOR_RESET);

    run_test_suite("Completion queue starts empty", test_completion_queue_starts_empty, client_data);
    run_test_suite("List empty directory", test_list_empty_directory, client_data);
    run_test_suite("Create + write + read roundtrip", test_create_write_read_roundtrip, client_data);
    run_test_suite("Duplicate create fails", test_duplicate_create_fails, client_data);
    run_test_suite("Directory/file conflicts", test_directory_file_conflicts, client_data);
    run_test_suite("Nested directory listing + size", test_nested_directory_listing_and_size, client_data);
    run_test_suite("Seek overwrite + OOB", test_seek_overwrite_and_oob, client_data);
    run_test_suite("Large write/read", test_large_write_read, client_data);
    run_test_suite("Close errors + permissions", test_close_fd_errors_and_permissions, client_data);
    run_test_suite("Deleted directory operations", test_deleted_directory_operations_fail, client_data);
    run_test_suite("Invalid inputs + edge cases", test_invalid_inputs_and_edge_cases, client_data);
    run_test_suite("Batched ops roundtrip", test_batched_operations_roundtrip, client_data);

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

// --------------------- Microkit entry points ------------------------//

void notified(microkit_channel client_id) {}

void init(void) {
    client_data = (client_t *)fs_data_base;
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_YELLOW);
    microkit_debug_puts(TEST_VERBOSITY, "TESTING: started\n");
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
    run_tests();

    mark_client_as_finished_running(client_data);
    notify_file_server(client_data, DONT_BLOCK_ON_NOTIFY);
    seL4_Yield();
}
