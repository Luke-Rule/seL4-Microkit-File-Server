#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fs_internal.h"

typedef struct {
	fs_state_t state;
	uint8_t *block_table;
	file_descriptor_t *file_descriptor_table;
	i_node_t *i_node_table;
	block_t *blocks;
} test_fs_fixture_t;

bool run_util_tests(void);
bool run_block_tests(void);
bool run_i_node_tests(void);
bool run_file_descriptor_tests(void);

bool run_test_case(const char *suite_name, const char *case_name, bool (*test_fn)(void));
int unit_test_failures(void);

bool expect_true(bool condition, const char *message);
bool expect_int_eq(int actual, int expected, const char *message);
bool expect_uint32_eq(uint32_t actual, uint32_t expected, const char *message);
bool expect_size_eq(size_t actual, size_t expected, const char *message);
bool expect_memory_eq(const void *actual, const void *expected, size_t length, const char *message);
void output_pass(const char *message);
void output_fail(const char *message);
void output_suite_pass(const char *message);
void output_suite_fail(const char *message);

bool test_fixture_init(test_fs_fixture_t *fixture);
void test_fixture_reset(test_fs_fixture_t *fixture);
void test_fixture_destroy(test_fs_fixture_t *fixture);
void test_fixture_init_root_dir(test_fs_fixture_t *fixture, uint8_t owner_id, permissions_t permissions);
void test_fixture_assign_inode(test_fs_fixture_t *fixture, uint32_t i_node_index, bool is_directory,
	uint8_t owner_id, permissions_t permissions);
void test_fixture_add_child(test_fs_fixture_t *fixture, uint32_t parent_i_node_index,
	const char *name, uint32_t child_i_node_index);
