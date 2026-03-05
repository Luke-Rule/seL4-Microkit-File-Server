
#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_api.h"
#include "fs_shared.h"
#include "test_utils.h"

// This file is built as client0.elf for the multi-client test system.

uintptr_t fs_data_base;
client_t *client_data;

int tests_passed = 0;
int tests_failed = 0;

static bool ensure_clean_mc_root(void) {
	// Best-effort cleanup from previous runs.
	if (!delete_entry_allow_missing((const unsigned char *)"/__mc", "Delete /__mc (cleanup)", client_data)) {
		return false;
	}
	fs_result_t rc = send_create_directory_request("/__mc", PERM_PUBLIC, client_data);
	if (!expect_eq_int(rc, FS_OK, "Queue create /__mc")) {
		return false;
	}
	notify_file_server(client_data, 1);
	completion_queue_entry_t c;
	if (!get_completion(&c, "Create /__mc", client_data)) {
		return false;
	}
	if (!expect_eq_uint32(c.return_code, FS_OK, "Create /__mc returned OK")) {
		return false;
	}
	return true;
}

static bool run_multi_client_permissions_test(void) {
	test_suite_begin("Multi-client permissions + sync", client_data);

	if (!ensure_clean_mc_root()) {
		return false;
	}

	const unsigned char private_path[] = "/__mc/private.txt";
	const unsigned char public_path[] = "/__mc/public.txt";
	const unsigned char shared_path[] = "/__mc/shared.txt";
	const unsigned char secret[] = "secret";
	const unsigned char public_data[] = "public";
	const unsigned char aaaa[] = "aaaa";
	const unsigned char bbbb[] = "bbbb";

	if (!fs_test_create_and_write_file(private_path, PERM_PRIVATE, READ_WRITE_OP, secret, sizeof(secret), "Create private", client_data)) {
		return false;
	}
	if (!fs_test_create_and_write_file(public_path, PERM_PUBLIC, READ_WRITE_OP, public_data, sizeof(public_data), "Create public", client_data)) {
		return false;
	}
	if (!fs_test_create_and_write_file(shared_path, PERM_PUBLIC, READ_WRITE_OP, aaaa, sizeof(aaaa), "Create shared", client_data)) {
		return false;
	}

	// Phase 1: other clients should observe permission enforcement and be able to write shared.
	if (!fs_test_create_marker((const unsigned char *)"/__mc/phase1", "Create phase1 marker", client_data)) {
		return false;
	}

	if (!fs_test_await_exists((const unsigned char *)"/__mc/client2_done1", "Wait client2 done1", 2000, client_data)) {
		return false;
	}
	if (!fs_test_await_exists((const unsigned char *)"/__mc/client3_done1", "Wait client3 done1", 2000, client_data)) {
		return false;
	}

	// Validate shared was modified by client3.
	if (!fs_test_open_read_expect(shared_path, bbbb, sizeof(bbbb), "Verify shared after client3 write", client_data)) {
		return false;
	}

	// Phase 2: lock down public + shared for other clients.
	fs_result_t rc = send_set_entry_permissions_request(public_path, PERM_PRIVATE, client_data);
	if (!expect_eq_int(rc, FS_OK, "Queue set public->private")) {
		return false;
	}
	notify_file_server(client_data, 1);
	completion_queue_entry_t c_setp;
	if (!get_completion(&c_setp, "Set public->private", client_data)) {
		return false;
	}
	if (!expect_eq_uint32(c_setp.return_code, FS_OK, "Set public->private returned OK")) {
		return false;
	}

	rc = send_set_entry_permissions_request(shared_path, PERM_READ, client_data);
	if (!expect_eq_int(rc, FS_OK, "Queue set shared->read")) {
		return false;
	}
	notify_file_server(client_data, 1);
	completion_queue_entry_t c_set_shared;
	if (!get_completion(&c_set_shared, "Set shared->read", client_data)) {
		return false;
	}
	if (!expect_eq_uint32(c_set_shared.return_code, FS_OK, "Set shared->read returned OK")) {
		return false;
	}

	if (!fs_test_create_marker((const unsigned char *)"/__mc/phase2", "Create phase2 marker", client_data)) {
		return false;
	}

	if (!fs_test_await_exists((const unsigned char *)"/__mc/client2_done2", "Wait client2 done2", 2000, client_data)) {
		return false;
	}
	if (!fs_test_await_exists((const unsigned char *)"/__mc/client3_done2", "Wait client3 done2", 2000, client_data)) {
		return false;
	}

	// Owner can still read everything.
	if (!fs_test_open_read_expect(private_path, secret, sizeof(secret), "Owner reads private", client_data)) {
		return false;
	}

	output_suite_pass((unsigned char *)"Multi-client permissions + sync");
	return true;
}

void notified(microkit_channel ch) {}

void init(void) {
	client_data = (client_t *)fs_data_base;
	microkit_dbg_puts(ANSI_COLOR_YELLOW);
	microkit_dbg_puts("MULTI TEST client0: started\n");
	microkit_dbg_puts(ANSI_COLOR_RESET);

	bool pass = run_multi_client_permissions_test();
	if (!pass) {
		output_fail((unsigned char *)"Multi-client permissions + sync");
	}

	//signal completion debug log
	microkit_dbg_puts(ANSI_COLOR_GREEN);
	microkit_dbg_puts("0 DONE\n");
	microkit_dbg_puts(ANSI_COLOR_RESET);
}
