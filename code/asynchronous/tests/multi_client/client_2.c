
#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../../debug_output.h"

#include "../../fs/include/fs_api.h"
#include "../../fs/include/fs_shared.h"
#include "../include/test_utils.h"

uintptr_t fs_data_base;
client_t *client_data;

int tests_passed = 0;
int tests_failed = 0;

static bool run_client(void) {
	test_suite_begin("Multi-client: client2 writes shared", client_data);

	const unsigned char private_path[] = "/__mc/private.txt";
	const unsigned char shared_path[] = "/__mc/shared.txt";
	const unsigned char bbbb[] = "bbbb";
	const unsigned char xdir_file[] = "/__mc/x_only/inside.txt";
	const unsigned char xdir_data[] = "inside";
	const unsigned char rwdir_file[] = "/__mc/rw_no_x/public.txt";

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase1", "Wait phase1", client_data)) {
		return false;
	}

	test_begin("Other client cannot open private for write");
	if (!fs_test_open_expect_rc(WRITE_OP, private_path, FS_ERR_PERMISSION, "Open private write expects denied", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot open private for write");

	test_begin("Other client can modify shared public file");
	if (!fs_test_open_write_close(shared_path, bbbb, sizeof(bbbb), "Open shared RW", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"Other client can modify shared public file");

	if (!fs_test_create_marker((const unsigned char *)"/__mc/client3_done1", "Create client3_done1", client_data)) {
		return false;
	}

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase2", "Wait phase2", client_data)) {
		return false;
	}

	test_begin("After lock-down, shared is not writable");
	if (!fs_test_open_expect_rc(WRITE_OP, shared_path, FS_ERR_PERMISSION, "Open shared write expects denied", client_data)) {
		return false;
	}
	if (!fs_test_open_read_expect(shared_path, bbbb, sizeof(bbbb), "Read shared after lock-down", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"After lock-down, shared is not writable");

	test_begin("Other client cannot change permissions on shared");
	if (!fs_test_set_perm_expect_rc(shared_path, PERM_PUBLIC, FS_ERR_PERMISSION, "Set perm shared expects denied", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot change permissions on shared");

	if (!fs_test_create_marker((const unsigned char *)"/__mc/client3_done2", "Create client3_done2", client_data)) {
		return false;
	}

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase3", "Wait phase3", client_data)) {
		return false;
	}

	test_begin("Other client cannot create in execute-only directory");
	if (!fs_test_create_file_expect_rc(
			(const unsigned char *)"/__mc/x_only/client2_new.txt",
			PERM_PUBLIC,
			READ_WRITE_OP,
			FS_ERR_PERMISSION,
			"Create in x_only expects denied",
			client_data)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot create in execute-only directory");

	test_begin("Other client can read file inside execute-only directory");
	if (!fs_test_open_read_expect(xdir_file, xdir_data, sizeof(xdir_data), "Read file in x_only", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"Other client can read file inside execute-only directory");

	if (!fs_test_create_marker((const unsigned char *)"/__mc/client3_done3", "Create client3_done3", client_data)) {
		return false;
	}

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase4", "Wait phase4", client_data)) {
		return false;
	}

	test_begin("Other client cannot traverse directory without execute");
	if (!fs_test_open_expect_rc(READ_OP, rwdir_file, FS_ERR_PERMISSION, "Open file in rw_no_x expects denied", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot traverse directory without execute");

	if (!fs_test_create_marker((const unsigned char *)"/__mc/client3_done4", "Create client3_done4", client_data)) {
		return false;
	}

	output_suite_pass((unsigned char *)"Multi-client: client2 writes shared");
	return true;
}

void notified(microkit_channel ch) {
	(void)ch;
}

void init(void) {
	client_data = (client_t *)fs_data_base;
	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, "\nMULTI TEST client 2: started\n");

	bool pass = run_client();
	if (!pass) {
		output_fail((unsigned char *)"Multi-client: client2 writes shared");
	}

	microkit_debug_puts(TEST_VERBOSITY, "\nMULTI TEST client 2: finished\n");
	mark_client_as_finished_running(client_data);
	notify_file_server(client_data, DONT_BLOCK_ON_NOTIFY);
	seL4_Yield();
}
