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

static bool run_client(void) {
	test_suite_begin("Multi-client: client1 checks perms", fs_buffer_base);

	const unsigned char private_path[] = "/__mc/private.txt";
	const unsigned char public_read_path[] = "/__mc/public_read.txt";
	const unsigned char shared_path[] = "/__mc/shared.txt";
	const unsigned char public_data[] = "public";
	const unsigned char bbbb[] = "bbbb";
	const unsigned char xdir_file[] = "/__mc/x_only/inside.txt";
	const unsigned char xdir_data[] = "inside";
	const unsigned char rwdir_file[] = "/__mc/rw_no_x/public.txt";

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase1", "Wait phase1", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	test_begin("Other client cannot open private file");
	if (!fs_test_open_expect_rc(READ_OP, private_path, FS_ERR_PERMISSION, "Open private expects permission", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot open private file");

	test_begin("Other client can read public file");
	if (!fs_test_open_read_expect(public_read_path, public_data, sizeof(public_data), "Open+read public", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Other client can read public file");

	test_begin("Other client cannot write to public read file");
	if (!fs_test_open_expect_rc(WRITE_OP, public_read_path, FS_ERR_PERMISSION, "Open public write expects permission", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot write to public read file");

	test_begin("Other client cannot change permissions on owner's file");
	if (!fs_test_set_perm_expect_rc(public_read_path, PERM_PRIVATE, FS_ERR_PERMISSION, "Set perm on public expects denied", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot change permissions on owner's file");

	test_begin("Other client cannot delete private file");
	if (!fs_test_delete_expect_rc(private_path, FS_ERR_PERMISSION, "Delete private expects denied", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot delete private file");

	if (!fs_test_create_marker((const unsigned char *)"/__mc/client2_done1", "Create client2_done1", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase2", "Wait phase2", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	test_begin("After lock-down, public becomes private for other clients");
	if (!fs_test_open_expect_rc(READ_OP, public_read_path, FS_ERR_PERMISSION, "Open public after private expects denied", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"After lock-down, public becomes private for other clients");

	test_begin("Shared becomes read-only for other clients");
	if (!fs_test_open_expect_rc(READ_WRITE_OP, shared_path, FS_ERR_PERMISSION, "Open shared RW expects denied", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	if (!fs_test_open_read_expect(shared_path, bbbb, sizeof(bbbb), "Open+read shared RO", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Shared becomes read-only for other clients");

	if (!fs_test_create_marker((const unsigned char *)"/__mc/client2_done2", "Create client2_done2", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase3", "Wait phase3", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	test_begin("Other client cannot create in execute-only directory");
	if (!fs_test_create_file_expect_rc((const unsigned char *)"/__mc/x_only/client1_new.txt", PERM_PUBLIC, READ_WRITE_OP, FS_ERR_PERMISSION, "Create in x_only expects denied", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot create in execute-only directory");

	test_begin("Other client can read file inside execute-only directory");
	if (!fs_test_open_read_expect(xdir_file, xdir_data, sizeof(xdir_data), "Read file in x_only", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Other client can read file inside execute-only directory");

	if (!fs_test_create_marker((const unsigned char *)"/__mc/client2_done3", "Create client2_done3", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	if (!fs_test_await_exists((const unsigned char *)"/__mc/phase4", "Wait phase4", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	test_begin("Other client cannot traverse directory without execute");
	if (!fs_test_open_expect_rc(READ_OP, rwdir_file, FS_ERR_PERMISSION, "Open file in rw_no_x expects denied", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}
	output_pass((unsigned char *)"Other client cannot traverse directory without execute");

	if (!fs_test_create_marker((const unsigned char *)"/__mc/client2_done4", "Create client2_done4", fs_buffer_base, FILE_SERVER_CHANNEL_ID)) {
		return false;
	}

	output_suite_pass((unsigned char *)"Multi-client: client1 checks perms");
	return true;
}

void notified(microkit_channel ch) {
	(void)ch;
}

void init(void) {
	fs_buffer_base = (uint8_t *)fs_data_base;
	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, "\nMULTI TEST client 1: started\n");

	if (!run_client()) {
		output_fail((unsigned char *)"Multi-client: client1 checks perms");
	}

	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, "\nMULTI TEST client 1: finished\n");
	mark_client_as_finished_running(fs_buffer_base);
	microkit_notify(FILE_SERVER_CHANNEL_ID);
	seL4_Yield();
}
