#include <microkit.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../debug_output.h"

#include "../../fs/include/fs_api.h"
#include "../include/test_utils.h"

uintptr_t fs_data_base;
uint8_t *fs_buffer_base;

int tests_passed = 0;
int tests_failed = 0;

static bool ensure_clean_mc_root(void) {
	/* Client 0 owns the shared multi-client fixture setup. */
	if (!delete_entry_allow_missing((const unsigned char *)"/__mc", "Delete /__mc (cleanup)", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	return expect_eq_int(
		send_create_directory_request((const unsigned char *)"/__mc", PERM_PUBLIC, fs_buffer_base, FILE_SERVER_CHANNEL_ID),
		FS_OK,
		"Create /__mc returned OK");
}

static bool run_multi_client_permissions_test(void) {
	/*
	 * Client 0 acts as the coordinator for the multi-client permission tests.
	 * It creates the shared fixture, advances the phase markers, and validates
	 * the final owner-visible state after the other two clients exercise access
	 * control from non-owner contexts.
	 */
	test_suite_begin("Multi-client permissions + sync", fs_buffer_base);

	if (!ensure_clean_mc_root()) {
		return false;
	}

	const unsigned char private_path[] = "/__mc/private.txt";
	const unsigned char public_read_path[] = "/__mc/public_read.txt";
	const unsigned char shared_path[] = "/__mc/shared.txt";
	const unsigned char secret[] = "secret";
	const unsigned char public_read_data[] = "public";
	const unsigned char aaaa[] = "aaaa";
	const unsigned char bbbb[] = "bbbb";
	const unsigned char xdir[] = "/__mc/x_only";
	const unsigned char xdir_file[] = "/__mc/x_only/inside.txt";
	const unsigned char xdir_data[] = "inside";
	const unsigned char rwdir[] = "/__mc/rw_no_x";
	const unsigned char rwdir_file[] = "/__mc/rw_no_x/public.txt";
	const unsigned char rwdir_data[] = "public-in-rw";

	/* Initial fixture: one private file, one read-only public file, one writable shared file. */
	if (!fs_test_create_and_write_file(private_path, PERM_PRIVATE, READ_WRITE_OP, secret, sizeof(secret), "Create private", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	if (!fs_test_create_and_write_file(public_read_path, PERM_READ, READ_WRITE_OP, public_read_data, sizeof(public_read_data), "Create public read only", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	if (!fs_test_create_and_write_file(shared_path, PERM_PUBLIC, READ_WRITE_OP, aaaa, sizeof(aaaa), "Create shared", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	/* Phase 1: other clients verify baseline permissions and mutate the shared file. */
	if (!fs_test_create_marker((const unsigned char *)"/__mc/phase1", "Create phase1 marker", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	if (!fs_test_await_exists((const unsigned char *)"/__mc/client2_done1", "Wait client2 done1", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	if (!fs_test_await_exists((const unsigned char *)"/__mc/client3_done1", "Wait client3 done1", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	if (!fs_test_open_read_expect(shared_path, bbbb, sizeof(bbbb), "Verify shared after client3 write", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	/* Phase 2: tighten permissions and confirm non-owners now lose access. */
	if (!expect_eq_int(send_set_entry_permissions_request(public_read_path, PERM_PRIVATE, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_OK, "Set public->private returned OK")) {
		return false;
	}
	if (!expect_eq_int(send_set_entry_permissions_request(shared_path, PERM_READ, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_OK, "Set shared->read returned OK")) {
		return false;
	}

	if (!fs_test_create_marker((const unsigned char *)"/__mc/phase2", "Create phase2 marker", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	if (!fs_test_await_exists((const unsigned char *)"/__mc/client2_done2", "Wait client2 done2", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	if (!fs_test_await_exists((const unsigned char *)"/__mc/client3_done2", "Wait client3 done2", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	if (!fs_test_open_read_expect(private_path, secret, sizeof(secret), "Owner reads private", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	/* Phase 3: execute-only directory allows traversal but not child creation. */
	if (!expect_eq_int(send_create_directory_request(xdir, PERM_EXECUTE, fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_OK, "Create x_only dir returned OK")) {
		return false;
	}
	if (!fs_test_create_and_write_file(xdir_file, PERM_READ, READ_WRITE_OP, xdir_data, sizeof(xdir_data), "Create file in x_only", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	if (!fs_test_create_marker((const unsigned char *)"/__mc/phase3", "Create phase3 marker", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	if (!fs_test_await_exists((const unsigned char *)"/__mc/client2_done3", "Wait client2 done3", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	if (!fs_test_await_exists((const unsigned char *)"/__mc/client3_done3", "Wait client3 done3", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	/* Phase 4: directory without execute permission should block traversal entirely. */
	if (!expect_eq_int(send_create_directory_request(rwdir, (permissions_t)(PERM_READ | PERM_WRITE), fs_buffer_base, FILE_SERVER_CHANNEL_ID), FS_OK, "Create rw_no_x dir returned OK")) {
		return false;
	}
	if (!fs_test_create_and_write_file(rwdir_file, PERM_PUBLIC, READ_WRITE_OP, rwdir_data, sizeof(rwdir_data), "Create file in rw_no_x", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	if (!fs_test_create_marker((const unsigned char *)"/__mc/phase4", "Create phase4 marker", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	if (!fs_test_await_exists((const unsigned char *)"/__mc/client2_done4", "Wait client2 done4", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	if (!fs_test_await_exists((const unsigned char *)"/__mc/client3_done4", "Wait client3 done4", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	output_suite_pass((unsigned char *)"Multi-client permissions + sync");
	return true;
}

void notified(microkit_channel ch) {
	(void)ch;
}

void init(void) {
	fs_buffer_base = (uint8_t *)fs_data_base;
	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, "\nMULTI TEST client 0: started\n");

	if (!run_multi_client_permissions_test()) {
		output_fail((unsigned char *)"Multi-client permissions + sync");
	}

	microkit_debug_puts(TEST_VERBOSITY, "\nMULTI TEST client 0: finished\n");
	mark_client_as_finished_running(fs_buffer_base);
	microkit_notify(FILE_SERVER_CHANNEL_ID);
	seL4_Yield();
}
