#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "debug_output.h"

#include "test_utils.h"
#include "fs_api.h"

extern int tests_passed;
extern int tests_failed;

// ------------------------------ Utility functions ------------------------------- //

#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

static void clear_all_client_buffers(client_t *client_data) {
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        client_data->submission_buffer_table[i] = 0;
        client_data->completion_buffer_table[i] = 0;
        for (size_t j = 0; j < CLIENT_BUFFER_SIZE; j++) {
            client_data->submission_buffers[i].data[j] = 0;
            client_data->completion_buffers[i].data[j] = 0;
        }
    }
    return;
}

void test_suite_begin(char *msg, client_t *client_data) {
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\n===== ");
    microkit_dbg_puts(msg);
    microkit_dbg_puts(" =====\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    clear_all_client_buffers(client_data);
}

void test_begin(char *msg) {
    microkit_dbg_puts(ANSI_COLOR_YELLOW);
    microkit_dbg_puts("\nTest: ");
    microkit_dbg_puts(msg);
    microkit_dbg_puts("\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
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

    notify_file_server(client_data, 1);
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

    notify_file_server(client_data, 1);
    completion_queue_entry_t c;
    if (!get_completion(&c, "Create /__tests", client_data)) {
        return false;
    }
    if (!expect_eq_uint32(c.return_code, FS_OK, "Create /__tests returned OK")) {
        return false;
    }

    return true;
}

void output_suite_pass(unsigned char *msg) {
    microkit_dbg_puts(ANSI_COLOR_GREEN);
    microkit_dbg_puts("[PASS] ");
    microkit_dbg_puts((const char *)msg);
    microkit_dbg_puts("\n");
    microkit_dbg_puts(ANSI_COLOR_RESET);
}

void output_pass(unsigned char *msg) {
    microkit_dbg_puts(ANSI_COLOR_GREEN);
    microkit_dbg_puts("[PASS] ");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    microkit_dbg_puts((const char *)msg);
    microkit_dbg_puts("\n");
}

void output_fail(unsigned char *msg) {
    microkit_dbg_puts(ANSI_COLOR_RED);
    microkit_dbg_puts("[FAIL] ");
    microkit_dbg_puts(ANSI_COLOR_RESET);
    microkit_dbg_puts((const char *)msg);
    microkit_dbg_puts("\n");
}

typedef bool (*test_fn_t)(void);

void run_test_suite(const char *name, test_fn_t test, client_t *client_data) {
    test_suite_begin((char *)name, client_data);

    bool pass = test();
    if (pass) {
        tests_passed++;
        microkit_dbg_putc('\n');
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

    microkit_debug_puts(ANSI_COLOR_RED);
    microkit_debug_puts("[ERROR] ");
    microkit_debug_puts(ANSI_COLOR_RESET);
    microkit_debug_puts(name);
    microkit_debug_puts(": expected ");
    microkit_debug_put32((uint32_t)expected);
    microkit_debug_puts(" but got ");
    microkit_debug_put32((uint32_t)actual);
    microkit_debug_puts("\n");

    return 0;
}

int expect_not_eq_int(int actual, int not_expected, const char *name) {
    if (actual != not_expected) {
        return 1;
    }

    microkit_debug_puts(ANSI_COLOR_RED);
    microkit_debug_puts("[ERROR] ");
    microkit_debug_puts(ANSI_COLOR_RESET);
    microkit_debug_puts(name);
    microkit_debug_puts(": did not expect ");
    microkit_debug_put32((uint32_t)not_expected);
    microkit_debug_puts("\n");

    return 0;
}

int expect_eq_uint32(uint32_t actual, uint32_t expected, const char *name) {
    if (actual == expected) {
        return 1;
    }

    microkit_debug_puts(ANSI_COLOR_RED);
    microkit_debug_puts("[ERROR] ");
    microkit_debug_puts(ANSI_COLOR_RESET);
    microkit_debug_puts(name);
    microkit_debug_puts(": expected ");
    microkit_debug_put32(expected);
    microkit_debug_puts(" but got ");
    microkit_debug_put32(actual);
    microkit_debug_puts("\n");

    return 0;
}

int expect_eq_uint8(uint8_t actual, uint8_t expected, const char *name) {
    if (actual == expected) {
        return 1;
    }

    microkit_debug_puts(ANSI_COLOR_RED);
    microkit_debug_puts("[ERROR] ");
    microkit_debug_puts(ANSI_COLOR_RESET);
    microkit_debug_puts(name);
    microkit_debug_puts(": expected ");
    microkit_debug_put32((uint32_t)expected);
    microkit_debug_puts(" but got ");
    microkit_debug_put32((uint32_t)actual);
    microkit_debug_puts("\n");

    return 0;
}

int expect_true(bool cond, const char *name) {
    if (cond) {
        return 1;
    } 
    
    microkit_debug_puts(ANSI_COLOR_RED);
    microkit_debug_puts("[ERROR] ");
    microkit_debug_puts(ANSI_COLOR_RESET);
    microkit_debug_puts(name);
    microkit_debug_puts("\n");

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
            microkit_debug_puts(ANSI_COLOR_RED);
            microkit_debug_puts("[ERROR] ");
            microkit_debug_puts(ANSI_COLOR_RESET);
            microkit_debug_puts(test_message);
            microkit_debug_puts(": Expected: ");
            for (size_t j = 0; j < length; j++) {
                microkit_debug_putc(((const char *)expected)[j]);
                if (((const char *)expected)[j] == '\0') {
                    microkit_debug_putc(',');
                }
            }
            microkit_debug_puts(", Got: ");
            for (size_t j = 0; j < length; j++) {
                microkit_debug_putc(((const char *)fs_buffer_base)[j]);
                if (((const char *)fs_buffer_base)[j] == '\0') {
                    microkit_debug_putc(',');
                }
            }
            microkit_debug_puts("\n");
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
            microkit_debug_puts(ANSI_COLOR_RED);
            microkit_debug_puts("[ERROR] ");
            microkit_debug_puts(ANSI_COLOR_RESET);
            microkit_debug_puts(test_message);
            microkit_debug_puts(": Expected: ");
            for (size_t j = 0; j < length; j++) {
                microkit_debug_putc(((const char *)expected)[j]);
            }
            microkit_debug_puts(", Got: ");
            for (size_t j = 0; j < length; j++) {
                microkit_debug_putc(((const char *)actual)[j]);
            }
            microkit_debug_puts("\n");
            return 0;
        }
    }
    
    return 1;
}

int expect_eq_strings(const char *actual, const char *expected, const char *test_message) {
    size_t i = 0;
    while (actual[i] != '\0' && expected[i] != '\0') {
        if (actual[i] != expected[i]) {
            microkit_debug_puts(ANSI_COLOR_RED);
            microkit_debug_puts("[ERROR] ");
            microkit_debug_puts(ANSI_COLOR_RESET);
            microkit_debug_puts(test_message);
            microkit_debug_puts(": Expected: ");
            microkit_debug_puts(expected);
            microkit_debug_puts(", Got: ");
            microkit_debug_puts(actual);
            microkit_debug_puts("\n");
            return 0;
        }
        i++;
    }

    if (actual[i] != expected[i]) {
        microkit_debug_puts(ANSI_COLOR_RED);
        microkit_debug_puts("[ERROR] ");
        microkit_debug_puts(ANSI_COLOR_RESET);
        microkit_debug_puts(test_message);
        microkit_debug_puts(": Expected: ");
        microkit_debug_puts(expected);
        microkit_debug_puts(", Got: ");
        microkit_debug_puts(actual);
        microkit_debug_puts("\n");
        return 0;
    }

    return 1;
}