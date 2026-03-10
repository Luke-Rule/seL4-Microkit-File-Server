#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../fs/include/fs_api.h"
#include "test_common.h"

void test_suite_begin(char *msg, uint8_t *fs_buffer_base);
void test_begin(char *msg);
void run_test_suite(const char *name, test_fn_t test, uint8_t *fs_buffer_base);

bool delete_entry_allow_missing(const unsigned char *path, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id);
bool ensure_clean_test_root(uint8_t *fs_buffer_base, uint8_t channel_id);

bool fs_test_await_exists(const unsigned char *path, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id);
bool fs_test_create_marker(const unsigned char *path, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id);
bool fs_test_open_expect_rc(file_open_operations_t ops, const unsigned char *path, uint32_t expected_rc, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id);
bool fs_test_open_read_expect(const unsigned char *path, const unsigned char *expected, size_t expected_len, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id);
bool fs_test_open_write_close(const unsigned char *path, const unsigned char *payload, size_t payload_len, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id);
bool fs_test_create_and_write_file(const unsigned char *path, permissions_t perms, file_open_operations_t create_ops, const unsigned char *payload, size_t payload_len, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id);
bool fs_test_create_file_expect_rc(const unsigned char *path, permissions_t perms, file_open_operations_t create_ops, uint32_t expected_rc, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id);
bool fs_test_delete_expect_rc(const unsigned char *path, uint32_t expected_rc, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id);
bool fs_test_set_perm_expect_rc(const unsigned char *path, permissions_t perms, uint32_t expected_rc, const char *step_name, uint8_t *fs_buffer_base, uint8_t channel_id);
