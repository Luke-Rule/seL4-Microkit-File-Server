
#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_api.h"
#include "fs_shared.h"
#include "test_utils.h"

// This file is built as client1.elf for the multi-client test system.

uintptr_t fs_data_base;
client_t *client_data;

int tests_passed = 0;
int tests_failed = 0;

static bool run_client(void) {
	test_suite_begin("Multi-client: client1 checks perms", client_data);

	const unsigned char private_path[] = "/__mc/private.txt";
	const unsigned char public_path[] = "/__mc/public.txt";
	const unsigned char shared_path[] = "/__mc/shared.txt";
	const unsigned char public_data[] = "public";
	const unsigned char bbbb[] = "bbbb";

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase1", "Wait phase1", 2000, client_data)) {
		return false;
	}

	test_begin("Other client cannot open private file");
	if (!fs_test_open_expect_rc(READ_OP, private_path, FS_ERR_PERMISSION, "Open private expects permission", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot open private file");

	test_begin("Other client can read public file");
	if (!fs_test_open_read_expect(public_path, public_data, sizeof(public_data), "Open+read public", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"Other client can read public file");

	test_begin("Other client cannot change permissions on owner's file");
	if (!fs_test_set_perm_expect_rc(public_path, PERM_PRIVATE, FS_ERR_PERMISSION, "Set perm on public expects denied", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot change permissions on owner's file");

	test_begin("Other client cannot delete private file");
	if (!fs_test_delete_expect_rc(private_path, FS_ERR_PERMISSION, "Delete private expects denied", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot delete private file");

	if (!fs_test_create_marker((const unsigned char *)"/__mc/client2_done1", "Create client2_done1", client_data)) {
		return false;
	}

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase2", "Wait phase2", 2000, client_data)) {
		return false;
	}

	test_begin("After lock-down, public becomes private for other clients");
	if (!fs_test_open_expect_rc(READ_OP, public_path, FS_ERR_PERMISSION, "Open public after private expects denied", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"After lock-down, public becomes private for other clients");

	test_begin("Shared becomes read-only for other clients");
	if (!fs_test_open_expect_rc(READ_WRITE_OP, shared_path, FS_ERR_PERMISSION, "Open shared RW expects denied", client_data)) {
		return false;
	}
	if (!fs_test_open_read_expect(shared_path, bbbb, sizeof(bbbb), "Open+read shared RO", client_data)) {
		return false;
	}
	output_pass((unsigned char *)"Shared becomes read-only for other clients");

	if (!fs_test_create_marker((const unsigned char *)"/__mc/client2_done2", "Create client2_done2", client_data)) {
		return false;
	}

	output_suite_pass((unsigned char *)"Multi-client: client1 checks perms");
	return true;
}

void notified(microkit_channel ch) {}

void init(void) {
	client_data = (client_t *)fs_data_base;
	microkit_debug_puts(ANSI_COLOR_YELLOW);
	microkit_debug_puts("MULTI TEST client1: started\n");
	microkit_debug_puts(ANSI_COLOR_RESET);

	bool pass = run_client();
	if (!pass) {
		output_fail((unsigned char *)"Multi-client: client1 checks perms");
	}
	//signal completion debug log
	microkit_dbg_puts(ANSI_COLOR_GREEN);
	microkit_dbg_puts("1 DONE\n");
	microkit_dbg_puts(ANSI_COLOR_RESET);
}
