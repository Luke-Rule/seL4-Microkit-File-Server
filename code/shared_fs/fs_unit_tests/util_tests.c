#include <string.h>

#include "include/unit_test_utils.h"

#include "fs_utils.h"

static bool compare_names_reports_full_match(void)
{
	return expect_int_eq(compare_names((const unsigned char *)"alpha", (const unsigned char *)"alpha"),
		FULL_PATH_EQUAL, "matching names compare equal");
}

static bool compare_names_reports_segment_match(void)
{
	return expect_int_eq(compare_names((const unsigned char *)"dir/file", (const unsigned char *)"dir"),
		PATH_SEGMENT_EQUAL, "path segment match is detected");
}

static bool compare_names_reports_mismatch(void)
{
	return expect_int_eq(compare_names((const unsigned char *)"alpha", (const unsigned char *)"alpX"),
		FULL_PATH_NOT_EQUAL, "mismatching names compare unequal");
}

static bool valid_name_accepts_and_rejects_expected_inputs(void)
{
	unsigned char too_long[MAX_NAME_LENGTH];

	memset(too_long, 'a', sizeof(too_long));
	return expect_true(valid_name((const unsigned char *)"simple"), "simple name is valid") &&
		expect_true(!valid_name((const unsigned char *)""), "empty name is invalid") &&
		expect_true(!valid_name((const unsigned char *)"/rooted"), "leading slash is invalid") &&
		expect_true(!valid_name((const unsigned char *)"has/slash"), "embedded slash is invalid") &&
		expect_true(!valid_name(too_long), "unterminated max-length name is invalid");
}

static bool valid_permissions_checks_owner_and_mode_bits(void)
{
	i_node_t i_node;

	memset(&i_node, 0, sizeof(i_node));
	i_node.owner_id = 7;
	i_node.mode = (uint8_t)(PERM_READ << PERMISSION_BITS_START);

	return expect_true(valid_permissions(&i_node, 7, PERM_WRITE), "owner bypasses permission checks") &&
		expect_true(valid_permissions(&i_node, 1, PERM_READ), "public read bit is honored") &&
		expect_true(!valid_permissions(&i_node, 1, PERM_WRITE), "missing write bit is rejected");
}

static bool copy_helpers_preserve_and_truncate_as_expected(void)
{
	uint8_t dest_data[8] = {0};
	unsigned char dest_string[5] = {0};
	const uint8_t src_data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	size_t copied;

	copy_data_from_buffer(src_data, dest_data, sizeof(src_data));
	copied = copy_string_from_buffer((const unsigned char *)"abcdef", dest_string, sizeof(dest_string));

	return expect_memory_eq(dest_data, src_data, sizeof(src_data), "raw buffer copy preserves bytes") &&
		expect_size_eq(copied, sizeof(dest_string) - 1, "truncated string reports copied length") &&
		expect_memory_eq(dest_string, "abcd", sizeof(dest_string), "string copy truncates with terminator");
}

static bool zero_block_clears_entire_block(void)
{
	unsigned char block[BLOCK_SIZE];

	memset(block, 0xAB, sizeof(block));
	zero_block(block);
 for (size_t index = 0; index < sizeof(block); index++) {
		if (block[index] != 0) {
			return expect_true(false, "zero_block clears all bytes");
		}
	}

	return true;
}

bool run_util_tests(void)
{
	bool passed = true;

	passed = run_test_case("fs_utils", "compare_names full match", compare_names_reports_full_match) && passed;
	passed = run_test_case("fs_utils", "compare_names segment match", compare_names_reports_segment_match) && passed;
	passed = run_test_case("fs_utils", "compare_names mismatch", compare_names_reports_mismatch) && passed;
	passed = run_test_case("fs_utils", "valid_name and valid_permissions", valid_name_accepts_and_rejects_expected_inputs) && passed;
	passed = run_test_case("fs_utils", "permission checks", valid_permissions_checks_owner_and_mode_bits) && passed;
	passed = run_test_case("fs_utils", "copy helpers", copy_helpers_preserve_and_truncate_as_expected) && passed;
	passed = run_test_case("fs_utils", "zero_block", zero_block_clears_entire_block) && passed;

	return passed;
}
