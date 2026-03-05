
#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_api.h"
#include "fs_shared.h"
#include "test_utils.h"

// This file is built as client2.elf for the multi-client test system.

uintptr_t fs_data_base;
client_t *client_data;

int tests_passed = 0;
int tests_failed = 0;

static bool run_client(void) {
	test_suite_begin("Multi-client: client2 writes shared", client_data);

	const unsigned char private_path[] = "/__mc/private.txt";
	const unsigned char shared_path[] = "/__mc/shared.txt";
	const unsigned char bbbb[] = "bbbb";

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase1", "Wait phase1", 2000, client_data)) {
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

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase2", "Wait phase2", 2000, client_data)) {
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

	output_suite_pass((unsigned char *)"Multi-client: client2 writes shared");
	return true;
}

void notified(microkit_channel ch) {
	(void)ch;
}

void init(void) {
	client_data = (client_t *)fs_data_base;
	microkit_debug_puts(ANSI_COLOR_YELLOW);
	microkit_debug_puts("MULTI TEST client2: started\n");
	microkit_debug_puts(ANSI_COLOR_RESET);

	bool pass = run_client();
	if (!pass) {
		output_fail((unsigned char *)"Multi-client: client2 writes shared");
	}
	// TODO change file names
	//signal completion debug log
	microkit_dbg_puts(ANSI_COLOR_GREEN);
	microkit_dbg_puts("2 DONE\n");
	microkit_dbg_puts(ANSI_COLOR_RESET);
}
