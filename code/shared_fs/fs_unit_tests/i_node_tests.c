#include <string.h>

#include "include/unit_test_utils.h"

#include "fs_i_node_manager.h"

static bool allocate_i_node_returns_first_available_entry(void)
{
	test_fs_fixture_t fixture;
	i_node_result_t result;
	bool passed;

	if (!test_fixture_init(&fixture)) {
		return false;
	}

	result = allocate_i_node(&fixture.state);
	passed = expect_uint32_eq(result.return_code, FS_OK, "inode allocation succeeds") &&
		expect_int_eq(result.index, 0, "first inode allocation returns index 0") &&
		expect_true((fixture.i_node_table[0].mode & IN_USE_BIT_SET) != 0, "allocated inode marked in use");

	test_fixture_destroy(&fixture);
	return passed;
}

static bool release_i_node_releases_direct_and_indirect_blocks(void)
{
	test_fs_fixture_t fixture;
	i_node_t *i_node;
	size_t *indirect_entries;
	bool passed;

	if (!test_fixture_init(&fixture)) {
		return false;
	}

	test_fixture_assign_inode(&fixture, 5, false, 0, PERM_PUBLIC);
	i_node = &fixture.i_node_table[5];
	i_node->blocks_used = DIRECT_BLOCKS_PER_INODE + 2;
	for (size_t index = 0; index < DIRECT_BLOCKS_PER_INODE; index++) {
		i_node->block_indices[index] = index + 1;
		fixture.block_table[index + 1] = 1;
	}
	i_node->block_indices[DIRECT_BLOCKS_PER_INODE] = 99;
	fixture.block_table[99] = 1;
	fixture.block_table[120] = 1;
	fixture.block_table[121] = 1;
	indirect_entries = (size_t *)&fixture.blocks[99].data;
	indirect_entries[0] = 120;
	indirect_entries[1] = 121;

	release_i_node(&fixture.state, 5);
	passed = expect_uint32_eq(fixture.i_node_table[5].mode, 0, "released inode mode resets to zero") &&
		expect_uint32_eq(fixture.block_table[1], 0, "direct block 1 released") &&
		expect_uint32_eq(fixture.block_table[DIRECT_BLOCKS_PER_INODE], 0, "last direct block released") &&
		expect_uint32_eq(fixture.block_table[120], 0, "first indirect data block released") &&
		expect_uint32_eq(fixture.block_table[121], 0, "second indirect data block released");

	test_fixture_destroy(&fixture);
	return passed;
}

static bool get_i_node_index_resolves_nested_paths_and_parent_requests(void)
{
	test_fs_fixture_t fixture;
	i_node_result_t nested;
	i_node_result_t parent;
	bool passed;

	if (!test_fixture_init(&fixture)) {
		return false;
	}

	test_fixture_init_root_dir(&fixture, 0, PERM_PUBLIC);
	test_fixture_assign_inode(&fixture, 1, true, 0, PERM_PUBLIC);
	test_fixture_assign_inode(&fixture, 2, false, 0, PERM_PUBLIC);
	test_fixture_add_child(&fixture, ROOT_DIRECTORY_I_NODE_INDEX, "sub", 1);
	test_fixture_add_child(&fixture, 1, "leaf.txt", 2);

	nested = get_i_node_index(&fixture.state, (unsigned char *)"/sub/leaf.txt", ROOT_DIRECTORY_I_NODE_INDEX, 0, GET_TARGET_I_NODE);
	parent = get_i_node_index(&fixture.state, (unsigned char *)"/sub/leaf.txt", ROOT_DIRECTORY_I_NODE_INDEX, 0, GET_PARENT_I_NODE);
	passed = expect_uint32_eq(nested.return_code, FS_OK, "nested lookup succeeds") &&
		expect_int_eq(nested.index, 2, "nested lookup returns leaf inode") &&
		expect_uint32_eq(parent.return_code, FS_OK, "parent lookup succeeds") &&
		expect_int_eq(parent.index, 1, "parent lookup returns containing directory");

	test_fixture_destroy(&fixture);
	return passed;
}

static bool get_i_node_index_rejects_invalid_or_forbidden_paths(void)
{
	test_fs_fixture_t fixture;
	i_node_result_t invalid_relative;
	i_node_result_t missing;
	i_node_result_t denied;
	i_node_result_t file_midpath;
	bool passed;

	if (!test_fixture_init(&fixture)) {
		return false;
	}

	test_fixture_init_root_dir(&fixture, 0, PERM_PUBLIC);
	test_fixture_assign_inode(&fixture, 1, true, 1, PERM_PRIVATE);
	test_fixture_assign_inode(&fixture, 2, false, 0, PERM_PUBLIC);
	test_fixture_assign_inode(&fixture, 3, false, 0, PERM_PUBLIC);
	test_fixture_add_child(&fixture, ROOT_DIRECTORY_I_NODE_INDEX, "secret", 1);
	test_fixture_add_child(&fixture, ROOT_DIRECTORY_I_NODE_INDEX, "plain.txt", 2);
	test_fixture_add_child(&fixture, 1, "leaf.txt", 3);

	invalid_relative = get_i_node_index(&fixture.state, (unsigned char *)"secret/leaf.txt", ROOT_DIRECTORY_I_NODE_INDEX, 0, GET_TARGET_I_NODE);
	missing = get_i_node_index(&fixture.state, (unsigned char *)"/missing", ROOT_DIRECTORY_I_NODE_INDEX, 0, GET_TARGET_I_NODE);
	denied = get_i_node_index(&fixture.state, (unsigned char *)"/secret/leaf.txt", ROOT_DIRECTORY_I_NODE_INDEX, 0, GET_TARGET_I_NODE);
	file_midpath = get_i_node_index(&fixture.state, (unsigned char *)"/plain.txt/child", ROOT_DIRECTORY_I_NODE_INDEX, 0, GET_TARGET_I_NODE);
	passed = expect_uint32_eq(invalid_relative.return_code, FS_ERR_INVALID_PATH, "relative path is rejected") &&
		expect_uint32_eq(missing.return_code, FS_ERR_NOT_FOUND, "missing path reports not found") &&
		expect_uint32_eq(denied.return_code, FS_ERR_PERMISSION, "permission failure is propagated") &&
		expect_uint32_eq(file_midpath.return_code, FS_ERR_INVALID_PATH, "file cannot appear in middle of path");

	test_fixture_destroy(&fixture);
	return passed;
}

bool run_i_node_tests(void)
{
	bool passed = true;

	passed = run_test_case("fs_i_node_manager", "allocate inode", allocate_i_node_returns_first_available_entry) && passed;
	passed = run_test_case("fs_i_node_manager", "release inode", release_i_node_releases_direct_and_indirect_blocks) && passed;
	passed = run_test_case("fs_i_node_manager", "resolve nested path", get_i_node_index_resolves_nested_paths_and_parent_requests) && passed;
	passed = run_test_case("fs_i_node_manager", "reject invalid paths", get_i_node_index_rejects_invalid_or_forbidden_paths) && passed;

	return passed;
}
