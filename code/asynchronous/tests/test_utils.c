#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../../debug_output.h"

#include "../include/test_utils.h"
#include "../../fs/include/fs_api.h"

extern int tests_passed;
extern int tests_failed;

// ------------------------------ Utility functions ------------------------------- //

#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

#define MAX_TEST_WAIT 2000

static void clear_all_client_buffers(client_t *client_data) {
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        client_data->submission_buffer_table[i] = false;
        client_data->completion_buffer_table[i] = false;
        for (size_t j = 0; j < CLIENT_BUFFER_SIZE; j++) {
            client_data->submission_buffers[i].data[j] = 0;
            client_data->completion_buffers[i].data[j] = 0;
        }
    }
    return;
}

void test_suite_begin(char *msg, client_t *client_data) {
	seL4_Yield();
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_YELLOW);
    microkit_debug_puts(TEST_VERBOSITY, "\n===== ");
    microkit_debug_puts(TEST_VERBOSITY, msg);
    microkit_debug_puts(TEST_VERBOSITY, " =====\n");
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
    clear_all_client_buffers(client_data);
}

void test_begin(char *msg) {
	seL4_Yield();
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_YELLOW);
    microkit_debug_puts(TEST_VERBOSITY, "\nTest: ");
    microkit_debug_puts(TEST_VERBOSITY, msg);
    microkit_debug_puts(TEST_VERBOSITY, "\n");
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
}

bool get_completion(completion_queue_entry_t *out, const char *step_name, client_t *client_data) {
    fs_result_t rc = get_next_completion_entry(client_data, out);
    if (!expect_eq_int(rc, FS_OK, step_name)) {
        return false;
    }
    return true;
}

bool delete_entry_allow_missing(const unsigned char *path, const char *step_name, client_t *client_data) {
    fs_result_t rc = send_delete_entry_request(path, client_data);
    if (!expect_eq_int(rc, FS_OK, step_name)) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c;
    if (!get_completion(&c, step_name, client_data)) {
        return false;
    }

    if (c.return_code != FS_OK && c.return_code != FS_ERR_NOT_FOUND && c.return_code != FS_ERR_FILE_DESCRIPTOR_NOT_FOUND) {
        return expect_eq_uint32(c.return_code, FS_OK, step_name);
    }

    return true;
}

bool ensure_clean_test_root(client_t *client_data) {
    if (!delete_entry_allow_missing((const unsigned char *)"/__tests", "Delete /__tests (cleanup)", client_data)) {
        return false;
    }

    fs_result_t rc = send_create_directory_request("/__tests", READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue create /__tests")) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);
    completion_queue_entry_t c;
    if (!get_completion(&c, "Create /__tests", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c.return_code, FS_OK, "Create /__tests returned OK")) {
        return false;
    }

    return true;
}

// ------------------------------ FS test helper functions ------------------------------- //

static bool fs_test_seek0(uint32_t fd, client_t *client_data) {
    fs_result_t rc = send_seek_file_request(fd, 0, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue seek 0")) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_seek;
    if (!get_completion(&c_seek, "Seek", client_data)) {
        return false;
    }

    return expect_eq_uint32(c_seek.return_code, FS_OK, "Seek returned OK");
}

bool fs_test_await_exists(
    const unsigned char *path,
    const char *step_name,
    client_t *client_data
) {
    for (uint32_t i = 0; i < MAX_TEST_WAIT; i++) {
        fs_result_t rc = send_entry_exists_request(path, client_data);
        if (!expect_eq_int(rc, FS_OK, step_name)) {
            return false;
        }

        notify_file_server(client_data, BLOCK_ON_NOTIFY);

        completion_queue_entry_t c;
        if (!get_completion(&c, step_name, client_data)) {
            return false;
        }
        if (!expect_eq_uint32(c.return_code, FS_OK, step_name)) {
            return false;
        }

        if (c.parameter1 == 1) {
            return true;
        }

        seL4_Yield();
    }

    return expect_true(false, "Timed out waiting for marker to exist");
}

bool fs_test_create_marker(const unsigned char *path, const char *step_name, client_t *client_data) {
    fs_result_t rc = send_create_file_request(path, PERM_PUBLIC, READ_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, step_name)) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_create;
    if (!get_completion(&c_create, step_name, client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_create.return_code, FS_OK, step_name)) {
        return false;
    }

    uint32_t fd = c_create.parameter1;
    rc = send_close_file_request(fd, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue close marker")) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_close;
    if (!get_completion(&c_close, "Close marker", client_data)) {
        return false;
    }
    return expect_eq_uint32(c_close.return_code, FS_OK, "Close marker returned OK");
}

bool fs_test_open_expect_rc(
    file_open_operations_t ops,
    const unsigned char *path,
    uint32_t expected_rc,
    const char *step_name,
    client_t *client_data
) {
    fs_result_t rc = send_open_file_request(path, ops, client_data);
    if (!expect_eq_int(rc, FS_OK, step_name)) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_open;
    if (!get_completion(&c_open, step_name, client_data)) {
        return false;
    }

    if (!expect_eq_uint32(c_open.return_code, expected_rc, step_name)) {
        return false;
    }

    if (expected_rc == FS_OK) {
        uint32_t fd = c_open.parameter1;
        rc = send_close_file_request(fd, client_data);
        if (!expect_eq_int(rc, FS_OK, "Queue close")) {
            return false;
        }

        notify_file_server(client_data, BLOCK_ON_NOTIFY);

        completion_queue_entry_t c_close;
        if (!get_completion(&c_close, "Close", client_data)) {
            return false;
        }

        return expect_eq_uint32(c_close.return_code, FS_OK, "Close returned OK");
    }

    return true;
}

bool fs_test_open_read_expect(
    const unsigned char *path,
    const unsigned char *expected,
    size_t expected_len,
    const char *step_name,
    client_t *client_data
) {
    fs_result_t rc = send_open_file_request(path, READ_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, step_name)) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_open;
    if (!get_completion(&c_open, step_name, client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_open.return_code, FS_OK, "Open returned OK")) {
        return false;
    }

    uint32_t fd = c_open.parameter1;

    if (!fs_test_seek0(fd, client_data)) {
        return false;
    }

    rc = send_read_file_request(fd, expected_len, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue read")) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_read;
    if (!get_completion(&c_read, "Read", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_read.return_code, FS_OK, "Read returned OK")) {
        return false;
    }

    if (!expect_equal_to_client_buffer(
            expected, expected_len, "Read matches expected", (int)c_read.buffer_index, client_data)) {
        return false;
    }
    set_free_completion_buffer(client_data, (int)c_read.buffer_index);

    rc = send_close_file_request(fd, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue close")) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_close;
    if (!get_completion(&c_close, "Close", client_data)) {
        return false;
    }
    return expect_eq_uint32(c_close.return_code, FS_OK, "Close returned OK");
}

bool fs_test_open_write_close(
    const unsigned char *path,
    const unsigned char *payload,
    size_t payload_len,
    const char *step_name,
    client_t *client_data
) {
    fs_result_t rc = send_open_file_request(path, READ_WRITE_OP, client_data);
    if (!expect_eq_int(rc, FS_OK, step_name)) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_open;
    if (!get_completion(&c_open, step_name, client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_open.return_code, FS_OK, "Open returned OK")) {
        return false;
    }

    uint32_t fd = c_open.parameter1;

    if (!fs_test_seek0(fd, client_data)) {
        return false;
    }

    rc = send_write_file_request(fd, payload_len, payload, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue write")) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_write;
    if (!get_completion(&c_write, "Write", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_write.return_code, FS_OK, "Write returned OK")) {
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
    return expect_eq_uint32(c_close.return_code, FS_OK, "Close returned OK");
}

bool fs_test_create_and_write_file(
    const unsigned char *path,
    permissions_t perms,
    file_open_operations_t create_ops,
    const unsigned char *payload,
    size_t payload_len,
    const char *step_name,
    client_t *client_data
) {
    fs_result_t rc = send_create_file_request(path, perms, create_ops, client_data);
    if (!expect_eq_int(rc, FS_OK, step_name)) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_create;
    if (!get_completion(&c_create, step_name, client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_create.return_code, FS_OK, step_name)) {
        return false;
    }

    uint32_t fd = c_create.parameter1;

    if (!fs_test_seek0(fd, client_data)) {
        return false;
    }

    rc = send_write_file_request(fd, payload_len, payload, client_data);
    if (!expect_eq_int(rc, FS_OK, "Queue write")) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_write;
    if (!get_completion(&c_write, "Write", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_write.return_code, FS_OK, "Write returned OK")) {
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
    return expect_eq_uint32(c_close.return_code, FS_OK, "Close returned OK");
}

bool fs_test_create_file_expect_rc(
    const unsigned char *path,
    permissions_t perms,
    file_open_operations_t create_ops,
    uint32_t expected_rc,
    const char *step_name,
    client_t *client_data
) {
    fs_result_t rc = send_create_file_request(path, perms, create_ops, client_data);
    if (!expect_eq_int(rc, FS_OK, step_name)) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_create;
    if (!get_completion(&c_create, step_name, client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c_create.return_code, expected_rc, step_name)) {
        return false;
    }

    if (expected_rc == FS_OK) {
        uint32_t fd = c_create.parameter1;
        rc = send_close_file_request(fd, client_data);
        if (!expect_eq_int(rc, FS_OK, "Queue close")) {
            return false;
        }

        notify_file_server(client_data, BLOCK_ON_NOTIFY);

        completion_queue_entry_t c_close;
        if (!get_completion(&c_close, "Close", client_data)) {
            return false;
        }
        return expect_eq_uint32(c_close.return_code, FS_OK, "Close returned OK");
    }

    return true;
}

bool fs_test_delete_expect_rc(
    const unsigned char *path,
    uint32_t expected_rc,
    const char *step_name,
    client_t *client_data
) {
    fs_result_t rc = send_delete_entry_request(path, client_data);
    if (!expect_eq_int(rc, FS_OK, step_name)) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c_del;
    if (!get_completion(&c_del, step_name, client_data)) {
        return false;
    }

    return expect_eq_uint32(c_del.return_code, expected_rc, step_name);
}

bool fs_test_set_perm_expect_rc(
    const unsigned char *path,
    permissions_t perms,
    uint32_t expected_rc,
    const char *step_name,
    client_t *client_data
) {
    fs_result_t rc = send_set_entry_permissions_request(path, perms, client_data);
    if (!expect_eq_int(rc, FS_OK, step_name)) {
        return false;
    }

    notify_file_server(client_data, BLOCK_ON_NOTIFY);

    completion_queue_entry_t c;
    if (!get_completion(&c, step_name, client_data)) {
        return false;
    }

    return expect_eq_uint32(c.return_code, expected_rc, step_name);
}

void output_suite_pass(unsigned char *msg) {
	seL4_Yield();
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_GREEN);
    microkit_debug_puts(TEST_VERBOSITY, "\n===== [SUITE PASS] ");
    microkit_debug_puts(TEST_VERBOSITY, (const char *)msg);
    microkit_debug_puts(TEST_VERBOSITY, " =====\n");
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
}

void output_pass(unsigned char *msg) {
	seL4_Yield();
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_GREEN);
    microkit_debug_puts(TEST_VERBOSITY, "[PASS] ");
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
    microkit_debug_puts(TEST_VERBOSITY, (const char *)msg);
    microkit_debug_puts(TEST_VERBOSITY, "\n");
}

void output_fail(unsigned char *msg) {
	seL4_Yield();
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
    microkit_debug_puts(TEST_VERBOSITY, "\n===== [SUITE FAIL] ");
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
    microkit_debug_puts(TEST_VERBOSITY, (const char *)msg);
    microkit_debug_puts(TEST_VERBOSITY, " =====\n");
}

typedef bool (*test_fn_t)(void);

void run_test_suite(const char *name, test_fn_t test, client_t *client_data) {
    test_suite_begin((char *)name, client_data);

    bool pass = test();
    if (pass) {
        tests_passed++;
        microkit_debug_putc(TEST_VERBOSITY, '\n');
        output_suite_pass((unsigned char *)name);
        return;
    }

    tests_failed++;
    output_fail((unsigned char *)name);
}

// ------------------------------ Assertion functions ------------------------------- //

int expect_eq_int(int actual, int expected, const char *name) {
    if (actual == expected) {
        return 1;
    }

	seL4_Yield();
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
    microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
    microkit_debug_puts(TEST_VERBOSITY, name);
    microkit_debug_puts(TEST_VERBOSITY, ": expected ");
    microkit_debug_put32(TEST_VERBOSITY, (uint32_t)expected);
    microkit_debug_puts(TEST_VERBOSITY, " but got ");
    microkit_debug_put32(TEST_VERBOSITY, (uint32_t)actual);
    microkit_debug_puts(TEST_VERBOSITY, "\n");

    return 0;
}

int expect_not_eq_int(int actual, int not_expected, const char *name) {
    if (actual != not_expected) {
        return 1;
    }

	seL4_Yield();
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
    microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
    microkit_debug_puts(TEST_VERBOSITY, name);
    microkit_debug_puts(TEST_VERBOSITY, ": did not expect ");
    microkit_debug_put32(TEST_VERBOSITY, (uint32_t)not_expected);
    microkit_debug_puts(TEST_VERBOSITY, "\n");

    return 0;
}

int expect_eq_uint32(uint32_t actual, uint32_t expected, const char *name) {
    if (actual == expected) {
        return 1;
    }

	seL4_Yield();
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
    microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
    microkit_debug_puts(TEST_VERBOSITY, name);
    microkit_debug_puts(TEST_VERBOSITY, ": expected ");
    microkit_debug_put32(TEST_VERBOSITY, expected);
    microkit_debug_puts(TEST_VERBOSITY, " but got ");
    microkit_debug_put32(TEST_VERBOSITY, actual);
    microkit_debug_puts(TEST_VERBOSITY, "\n");

    return 0;
}

int expect_eq_uint8(uint8_t actual, uint8_t expected, const char *name) {
    if (actual == expected) {
        return 1;
    }

	seL4_Yield();
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
    microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
    microkit_debug_puts(TEST_VERBOSITY, name);
    microkit_debug_puts(TEST_VERBOSITY, ": expected ");
    microkit_debug_put32(TEST_VERBOSITY, (uint32_t)expected);
    microkit_debug_puts(TEST_VERBOSITY, " but got ");
    microkit_debug_put32(TEST_VERBOSITY, (uint32_t)actual);
    microkit_debug_puts(TEST_VERBOSITY, "\n");

    return 0;
}

int expect_true(bool cond, const char *name) {
    if (cond) {
        return 1;
    } 
    
	seL4_Yield();
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
    microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
    microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
    microkit_debug_puts(TEST_VERBOSITY, name);
    microkit_debug_puts(TEST_VERBOSITY, "\n");

    return 0;
}

int expect_equal_to_client_buffer(
    const unsigned char *expected,
    size_t length,
    const char *test_message,
    int buffer_index,
    client_t *client_data
) {
    uint8_t *fs_buffer_base = (uint8_t *)&client_data->completion_buffers[buffer_index];
    for (size_t i = 0; i < length; i++) {
        if (fs_buffer_base[i] != expected[i]) {
	        seL4_Yield();
            microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
            microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
            microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
            microkit_debug_puts(TEST_VERBOSITY, test_message);
            microkit_debug_puts(TEST_VERBOSITY, ": Expected: ");
            for (size_t j = 0; j < length; j++) {
                microkit_debug_putc(TEST_VERBOSITY, ((const char *)expected)[j]);
                if (((const char *)expected)[j] == '\0') {
                    microkit_debug_putc(TEST_VERBOSITY, ',');
                }
            }
            microkit_debug_puts(TEST_VERBOSITY, ", Got: ");
            for (size_t j = 0; j < length; j++) {
                microkit_debug_putc(TEST_VERBOSITY, ((const char *)fs_buffer_base)[j]);
                if (((const char *)fs_buffer_base)[j] == '\0') {
                    microkit_debug_putc(TEST_VERBOSITY, ',');
                }
            }
            microkit_debug_puts(TEST_VERBOSITY, "\n");
            return 0;
        }
    }
    
    return 1;
}

int expect_equal_to_buffer(
    const uint8_t *actual,
    const uint8_t *expected,
    size_t length,
    const char *test_message
) {
    for (size_t i = 0; i < length; i++) {
        if (actual[i] != expected[i]) {
	        seL4_Yield();
            microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
            microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
            microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
            microkit_debug_puts(TEST_VERBOSITY, test_message);
            microkit_debug_puts(TEST_VERBOSITY, ": Expected: ");
            for (size_t j = 0; j < length; j++) {
                microkit_debug_putc(TEST_VERBOSITY, ((const char *)expected)[j]);
            }
            microkit_debug_puts(TEST_VERBOSITY, ", Got: ");
            for (size_t j = 0; j < length; j++) {
                microkit_debug_putc(TEST_VERBOSITY, ((const char *)actual)[j]);
            }
            microkit_debug_puts(TEST_VERBOSITY, "\n");
            return 0;
        }
    }
    
    return 1;
}

int expect_eq_strings(const char *actual, const char *expected, const char *test_message) {
    size_t i = 0;
    while (actual[i] != '\0' && expected[i] != '\0') {
        if (actual[i] != expected[i]) {
	        seL4_Yield();
            microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
            microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
            microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
            microkit_debug_puts(TEST_VERBOSITY, test_message);
            microkit_debug_puts(TEST_VERBOSITY, ": Expected: ");
            microkit_debug_puts(TEST_VERBOSITY, expected);
            microkit_debug_puts(TEST_VERBOSITY, ", Got: ");
            microkit_debug_puts(TEST_VERBOSITY, actual);
            microkit_debug_puts(TEST_VERBOSITY, "\n");
            return 0;
        }
        i++;
    }

    if (actual[i] != expected[i]) {
        seL4_Yield();
        microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
        microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
        microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
        microkit_debug_puts(TEST_VERBOSITY, test_message);
        microkit_debug_puts(TEST_VERBOSITY, ": Expected: ");
        microkit_debug_puts(TEST_VERBOSITY, expected);
        microkit_debug_puts(TEST_VERBOSITY, ", Got: ");
        microkit_debug_puts(TEST_VERBOSITY, actual);
        microkit_debug_puts(TEST_VERBOSITY, "\n");
        return 0;
    }

    return 1;
}