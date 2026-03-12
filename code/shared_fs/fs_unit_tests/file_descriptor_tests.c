#include "include/unit_test_utils.h"

#include "fs_file_table_manager.h"

static bool get_file_descriptor_reports_missing_and_present_entries(void)
{
	test_fs_fixture_t fixture;
	file_descriptor_result_t missing;
	file_descriptor_result_t present;
	bool passed;

	if (!test_fixture_init(&fixture)) {
		return false;
	}

	fixture.file_descriptor_table[3].i_node_index = 17;
	fixture.file_descriptor_table[3].cursor_position = 99;

	missing = get_file_descriptor(&fixture.state, 0, MAX_OPEN_FILES_PER_CLIENT);
	present = get_file_descriptor(&fixture.state, 0, 3);
	passed = expect_uint32_eq(missing.return_code, FS_ERR_FILE_DESCRIPTOR_NOT_FOUND, "out-of-range fd lookup fails") &&
		expect_uint32_eq(present.return_code, FS_OK, "existing fd lookup succeeds") &&
		expect_uint32_eq(present.descriptor->i_node_index, 17, "lookup returns stored inode index") &&
		expect_size_eq(present.descriptor->cursor_position, 99, "lookup preserves cursor position");

	test_fixture_destroy(&fixture);
	return passed;
}

static bool add_i_node_to_fd_table_allocates_reuses_and_closes_descriptors(void)
{
	test_fs_fixture_t fixture;
	file_id_and_cursor_result_t created;
	file_id_and_cursor_result_t reused;
	fs_result_t closed;
	bool passed;

	if (!test_fixture_init(&fixture)) {
		return false;
	}

	test_fixture_assign_inode(&fixture, 4, false, 0, PERM_PUBLIC);
	created = add_i_node_to_fd_table(&fixture.state, 0, 4, READ_OP);
	fixture.file_descriptor_table[created.file_id].cursor_position = 12;
	reused = add_i_node_to_fd_table(&fixture.state, 0, 4, READ_OP);
	closed = close_file_by_i_node_index(&fixture.state, 0, 4);
	passed = expect_uint32_eq(created.return_code, FS_OK, "new fd allocation succeeds") &&
		expect_uint32_eq(created.file_id, 0, "first fd uses slot 0") &&
		expect_uint32_eq(reused.return_code, FS_OK, "reopening same inode reuses existing fd") &&
		expect_uint32_eq(reused.file_id, 0, "reused fd keeps same slot") &&
		expect_size_eq(reused.cursor_position, 12, "reused fd returns current cursor") &&
		expect_uint32_eq(closed, FS_OK, "close by inode succeeds") &&
		expect_uint32_eq(fixture.file_descriptor_table[0].i_node_index, UINT32_MAX, "closed fd resets to unused sentinel");

	test_fixture_destroy(&fixture);
	return passed;
}

static bool add_i_node_to_fd_table_enforces_permissions_and_capacity(void)
{
	test_fs_fixture_t fixture;
	file_id_and_cursor_result_t denied;
	file_id_and_cursor_result_t filled;
	file_id_and_cursor_result_t overflow;
	bool passed;
	const uint32_t capacity_test_inode = 900;

	if (!test_fixture_init(&fixture)) {
		return false;
	}

	test_fixture_assign_inode(&fixture, 9, false, 1, PERM_READ);
	test_fixture_assign_inode(&fixture, capacity_test_inode, false, 0, PERM_PUBLIC);
	denied = add_i_node_to_fd_table(&fixture.state, 0, 9, WRITE_OP);
	for (size_t index = 0; index < MAX_OPEN_FILES_PER_CLIENT; index++) {
		fixture.file_descriptor_table[index].i_node_index = (uint32_t)index;
	}
	filled = add_i_node_to_fd_table(&fixture.state, 0, capacity_test_inode, READ_OP);
	fixture.file_descriptor_table[7].i_node_index = UINT32_MAX;
	overflow = add_i_node_to_fd_table(&fixture.state, 0, capacity_test_inode, READ_OP);
	passed = expect_uint32_eq(denied.return_code, FS_ERR_PERMISSION, "permission denied when inode lacks requested mode") &&
		expect_uint32_eq(filled.return_code, FS_ERR_MAX_OPEN_FILES_REACHED, "full descriptor table is reported") &&
		expect_uint32_eq(overflow.return_code, FS_OK, "freed slot accepts new descriptor") &&
		expect_uint32_eq(overflow.file_id, 7, "new descriptor uses first freed slot");

	test_fixture_destroy(&fixture);
	return passed;
}

static bool is_i_node_open_tracks_open_state(void)
{
	test_fs_fixture_t fixture;
	bool passed;

	if (!test_fixture_init(&fixture)) {
		return false;
	}

	fixture.file_descriptor_table[0].i_node_index = 22;
	fixture.file_descriptor_table[1].i_node_index = UINT32_MAX;
	passed = expect_true(is_i_node_open(&fixture.state, 22), "opened inode is detected") &&
		expect_true(!is_i_node_open(&fixture.state, 23), "unopened inode is not detected");

	test_fixture_destroy(&fixture);
	return passed;
}

bool run_file_descriptor_tests(void)
{
	bool passed = true;

	passed = run_test_case("fs_file_table_manager", "lookup descriptors", get_file_descriptor_reports_missing_and_present_entries) && passed;
	passed = run_test_case("fs_file_table_manager", "allocate and close descriptors", add_i_node_to_fd_table_allocates_reuses_and_closes_descriptors) && passed;
	passed = run_test_case("fs_file_table_manager", "permissions and capacity", add_i_node_to_fd_table_enforces_permissions_and_capacity) && passed;
	passed = run_test_case("fs_file_table_manager", "is_i_node_open", is_i_node_open_tracks_open_state) && passed;

	return passed;
}
