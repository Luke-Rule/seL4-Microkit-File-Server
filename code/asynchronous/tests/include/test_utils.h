#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../../fs/include/fs_shared.h"
#include "test_common.h"

void test_suite_begin(char *msg, client_t *client_data);
void test_begin(char *msg);
bool get_completion(completion_queue_entry_t *out, const char *step_name, client_t *client_data);
bool delete_entry_allow_missing(const unsigned char *path, const char *step_name, client_t *client_data);
bool ensure_clean_test_root(client_t *client_data);
void run_test_suite(const char *name, test_fn_t test, client_t *client_data);

int expect_equal_to_client_buffer(
    const unsigned char *expected,
    size_t length,
    const char *test_message,
    int buffer_index,
    client_t *client_data
);

// ------------------------------ FS test helper functions ------------------------------- //

bool fs_test_await_exists(
    const unsigned char *path,
    const char *step_name,
    client_t *client_data
);

bool fs_test_create_marker(const unsigned char *path, const char *step_name, client_t *client_data);

bool fs_test_open_expect_rc(
    file_open_operations_t ops,
    const unsigned char *path,
    uint32_t expected_rc,
    const char *step_name,
    client_t *client_data
);

bool fs_test_open_read_expect(
    const unsigned char *path,
    const unsigned char *expected,
    size_t expected_len,
    const char *step_name,
    client_t *client_data
);

bool fs_test_open_write_close(
    const unsigned char *path,
    const unsigned char *payload,
    size_t payload_len,
    const char *step_name,
    client_t *client_data
);

bool fs_test_create_and_write_file(
    const unsigned char *path,
    permissions_t perms,
    file_open_operations_t create_ops,
    const unsigned char *payload,
    size_t payload_len,
    const char *step_name,
    client_t *client_data
);

bool fs_test_create_file_expect_rc(
    const unsigned char *path,
    permissions_t perms,
    file_open_operations_t create_ops,
    uint32_t expected_rc,
    const char *step_name,
    client_t *client_data
);

bool fs_test_delete_expect_rc(
    const unsigned char *path,
    uint32_t expected_rc,
    const char *step_name,
    client_t *client_data
);

bool fs_test_set_perm_expect_rc(
    const unsigned char *path,
    permissions_t perms,
    uint32_t expected_rc,
    const char *step_name,
    client_t *client_data
);
