#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/unit_test_utils.h"

#include "fs_block_manager.h"

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

static void output_with_color(const char *color, const char *prefix, const char *message,
	const char *suffix)
{
	printf("%s%s%s%s%s", color, prefix, message, suffix, ANSI_COLOR_RESET);
}

static void output_expectation_fail(const char *message, const char *details)
{
	printf("%s[ERROR] %s%s", ANSI_COLOR_RED, ANSI_COLOR_RESET, message);
	if (details != NULL && details[0] != '\0') {
		printf(": %s", details);
	}
	printf("\n");
}

bool expect_true(bool condition, const char *message)
{
	if (condition) {
		return true;
	}

	output_expectation_fail(message, "expected true");
	return false;
}

bool expect_int_eq(int actual, int expected, const char *message)
{
	char details[96];

	if (actual == expected) {
		return true;
	}

	snprintf(details, sizeof(details), "expected %d but got %d", expected, actual);
	output_expectation_fail(message, details);
	return false;
}

bool expect_uint32_eq(uint32_t actual, uint32_t expected, const char *message)
{
	char details[96];

	if (actual == expected) {
		return true;
	}

	snprintf(details, sizeof(details), "expected %u but got %u",
		(unsigned int)expected, (unsigned int)actual);
	output_expectation_fail(message, details);
	return false;
}

bool expect_size_eq(size_t actual, size_t expected, const char *message)
{
	char details[96];

	if (actual == expected) {
		return true;
	}

	snprintf(details, sizeof(details), "expected %zu but got %zu", expected, actual);
	output_expectation_fail(message, details);
	return false;
}

bool expect_memory_eq(const void *actual, const void *expected, size_t length, const char *message)
{
	if (memcmp(actual, expected, length) == 0) {
		return true;
	}

	output_expectation_fail(message, "memory regions differ");
	return false;
}

void output_pass(const char *message)
{
	output_with_color(ANSI_COLOR_GREEN, "[PASS] ", message, "\n");
}

void output_fail(const char *message)
{
	output_with_color(ANSI_COLOR_RED, "[FAIL] ", message, "\n");
}

void output_suite_pass(const char *message)
{
	output_with_color(ANSI_COLOR_GREEN, "\n===== [SUITE PASS] ", message, " =====\n");
}

void output_suite_fail(const char *message)
{
	output_with_color(ANSI_COLOR_RED, "\n===== [SUITE FAIL] ", message, " =====\n");
}

static void format_test_case_message(char *buffer, size_t buffer_length,
	const char *suite_name, const char *case_name)
{
	int written = snprintf(buffer, buffer_length, "%s: %s", suite_name, case_name);

	if (written < 0 || (size_t)written >= buffer_length) {
		buffer[buffer_length - 1] = '\0';
	}
}

bool run_test_case(const char *suite_name, const char *case_name, bool (*test_fn)(void))
{
	char message[160];
	bool passed;

	g_tests_run += 1;
	format_test_case_message(message, sizeof(message), suite_name, case_name);
	passed = test_fn();
	if (passed) {
		output_pass(message);
		return true;
	}

	g_tests_failed += 1;
	output_fail(message);
	return false;
}

int unit_test_failures(void)
{
	return g_tests_failed;
}

bool test_fixture_init(test_fs_fixture_t *fixture)
{
	memset(fixture, 0, sizeof(*fixture));

	fixture->block_table = calloc(MAX_NUMBER_OF_BLOCKS, sizeof(*fixture->block_table));
	fixture->file_descriptor_table = malloc(NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT * sizeof(*fixture->file_descriptor_table));
	fixture->i_node_table = calloc(MAX_NUMBER_OF_INODES, sizeof(*fixture->i_node_table));
	fixture->blocks = calloc(MAX_NUMBER_OF_BLOCKS, sizeof(*fixture->blocks));
	if (fixture->block_table == NULL || fixture->file_descriptor_table == NULL ||
		fixture->i_node_table == NULL || fixture->blocks == NULL) {
		output_fail("failed to allocate fixture storage");
		test_fixture_destroy(fixture);
		return false;
	}

	fixture->state.block_table = fixture->block_table;
	fixture->state.file_descriptor_table = fixture->file_descriptor_table;
	fixture->state.i_node_table = fixture->i_node_table;
	fixture->state.blocks = fixture->blocks;

	test_fixture_reset(fixture);
	return true;
}

void test_fixture_reset(test_fs_fixture_t *fixture)
{
	size_t total_fds = NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT;

	memset(fixture->block_table, 0, MAX_NUMBER_OF_BLOCKS * sizeof(*fixture->block_table));
	memset(fixture->i_node_table, 0, MAX_NUMBER_OF_INODES * sizeof(*fixture->i_node_table));
	memset(fixture->blocks, 0, MAX_NUMBER_OF_BLOCKS * sizeof(*fixture->blocks));
	for (size_t index = 0; index < total_fds; index++) {
		fixture->file_descriptor_table[index].i_node_index = UINT32_MAX;
		fixture->file_descriptor_table[index].cursor_position = 0;
		fixture->file_descriptor_table[index].valid_operations = 0;
	}
}

void test_fixture_destroy(test_fs_fixture_t *fixture)
{
	free(fixture->block_table);
	free(fixture->file_descriptor_table);
	free(fixture->i_node_table);
	free(fixture->blocks);
	memset(fixture, 0, sizeof(*fixture));
}

void test_fixture_assign_inode(test_fs_fixture_t *fixture, uint32_t i_node_index, bool is_directory,
	uint8_t owner_id, permissions_t permissions)
{
	i_node_t *i_node = &fixture->i_node_table[i_node_index];

	memset(i_node, 0, sizeof(*i_node));
	i_node->mode = IN_USE_BIT_SET | (uint8_t)(permissions << PERMISSION_BITS_START);
	if (is_directory) {
		i_node->mode |= IS_DIRECTORY_BIT_SET;
	}
	i_node->owner_id = owner_id;
	for (size_t index = 0; index <= DIRECT_BLOCKS_PER_INODE; index++) {
		i_node->block_indices[index] = 0;
	}
}

void test_fixture_init_root_dir(test_fs_fixture_t *fixture, uint8_t owner_id, permissions_t permissions)
{
	block_id_result_t root_block;

	test_fixture_assign_inode(fixture, ROOT_DIRECTORY_I_NODE_INDEX, true, owner_id, permissions);
	root_block = allocate_block(&fixture->state);
	if (root_block.return_code != FS_OK) {
		output_fail("failed to allocate root directory block");
		abort();
	}
	fixture->i_node_table[ROOT_DIRECTORY_I_NODE_INDEX].block_indices[0] = root_block.index;
	fixture->i_node_table[ROOT_DIRECTORY_I_NODE_INDEX].blocks_used = 1;
	memset(&fixture->blocks[root_block.index], 0, sizeof(block_t));
}

void test_fixture_add_child(test_fs_fixture_t *fixture, uint32_t parent_i_node_index,
	const char *name, uint32_t child_i_node_index)
{
	i_node_t *parent = &fixture->i_node_table[parent_i_node_index];
	child_entry_t *entries;
	size_t block_index;

	if (parent->blocks_used == 0) {
		block_id_result_t new_block = allocate_block(&fixture->state);
		if (new_block.return_code != FS_OK) {
			output_fail("failed to allocate directory block for child entry");
			abort();
		}
		parent->block_indices[0] = new_block.index;
		parent->blocks_used = 1;
	}

	block_index = parent->block_indices[0];
	entries = (child_entry_t *)&fixture->blocks[block_index].data;
	for (size_t index = 0; index < MAX_CHILD_ENTRIES_PER_BLOCK; index++) {
		if (entries[index].name[0] == '\0') {
			memset(entries[index].name, 0, sizeof(entries[index].name));
			strncpy((char *)entries[index].name, name, MAX_NAME_LENGTH - 1);
			entries[index].i_node_index = child_i_node_index;
			parent->entry_size += 1;
			return;
		}
	}

	output_fail("directory block is unexpectedly full");
	abort();
}

int main(void)
{
	char summary[96];
	bool passed = true;

	passed = run_util_tests() && passed;
	passed = run_block_tests() && passed;
	passed = run_i_node_tests() && passed;
	passed = run_file_descriptor_tests() && passed;

	snprintf(summary, sizeof(summary), "Ran %d test cases, %d failed.", g_tests_run, g_tests_failed);
	if (passed) {
		output_suite_pass(summary);
	} else {
		output_suite_fail(summary);
	}
	return passed ? 0 : 1;
}
