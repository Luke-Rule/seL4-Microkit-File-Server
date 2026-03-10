#include <string.h>

#include "include/unit_test_utils.h"

#include "fs_block_manager.h"

static bool allocate_block_returns_first_free_slot(void)
{
	test_fs_fixture_t fixture;
	block_id_result_t first;
	block_id_result_t second;
	bool passed;

	if (!test_fixture_init(&fixture)) {
		return false;
	}

	first = allocate_block(&fixture.state);
	second = allocate_block(&fixture.state);
	passed = expect_uint32_eq(first.return_code, FS_OK, "first allocation succeeds") &&
		expect_uint32_eq(first.index, 0, "first allocation returns block 0") &&
		expect_uint32_eq(second.return_code, FS_OK, "second allocation succeeds") &&
		expect_uint32_eq(second.index, 1, "second allocation returns block 1") &&
		expect_uint32_eq(fixture.block_table[0], 1, "first block marked used") &&
		expect_uint32_eq(fixture.block_table[1], 1, "second block marked used");

	test_fixture_destroy(&fixture);
	return passed;
}

static bool release_block_makes_slot_reusable(void)
{
	test_fs_fixture_t fixture;
	block_id_result_t first;
	block_id_result_t recycled;
	bool passed;

	if (!test_fixture_init(&fixture)) {
		return false;
	}

	first = allocate_block(&fixture.state);
	release_block(&fixture.state, first.index);
	recycled = allocate_block(&fixture.state);
	passed = expect_uint32_eq(recycled.return_code, FS_OK, "recycled allocation succeeds") &&
		expect_uint32_eq(recycled.index, first.index, "released block is reused first") &&
		expect_uint32_eq(fixture.block_table[first.index], 1, "reused block is marked in use again");

	test_fixture_destroy(&fixture);
	return passed;
}

static bool release_indirect_block_releases_referenced_blocks(void)
{
	test_fs_fixture_t fixture;
	size_t *entries;
	bool passed;

	if (!test_fixture_init(&fixture)) {
		return false;
	}

	fixture.block_table[3] = 1;
	fixture.block_table[7] = 1;
	fixture.block_table[11] = 1;
	entries = (size_t *)&fixture.blocks[2].data;
	entries[0] = 3;
	entries[1] = 7;
	entries[2] = 11;

	release_indirect_block(&fixture.state, 2, 3);
	passed = expect_uint32_eq(fixture.block_table[3], 0, "first indirect entry released") &&
		expect_uint32_eq(fixture.block_table[7], 0, "second indirect entry released") &&
		expect_uint32_eq(fixture.block_table[11], 0, "third indirect entry released");

	test_fixture_destroy(&fixture);
	return passed;
}

bool run_block_tests(void)
{
	bool passed = true;

	passed = run_test_case("fs_block_manager", "allocate block", allocate_block_returns_first_free_slot) && passed;
	passed = run_test_case("fs_block_manager", "release block", release_block_makes_slot_reusable) && passed;
	passed = run_test_case("fs_block_manager", "release indirect block", release_indirect_block_releases_referenced_blocks) && passed;

	return passed;
}
