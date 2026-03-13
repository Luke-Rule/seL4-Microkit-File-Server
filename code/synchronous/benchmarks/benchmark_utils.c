#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "fs_shared.h"
#include "../../debug_output.h"
#include "../../timing_helpers.h"

#include "benchmark_shared.h"
#include "benchmark_utils.h"

static bool expect_rc(int rc, const char *operation)
{
    if (rc == FS_OK) {
        return true;
    }

    microkit_debug_puts(TEST_VERBOSITY, operation);
    microkit_debug_puts(TEST_VERBOSITY, " failed with rc=");
    microkit_debug_put32(TEST_VERBOSITY, (uint32_t)rc);
    microkit_debug_puts(TEST_VERBOSITY, "\n");
    return false;
}

static bool expect_read_result(fs_result_read_t read_result,
                               const uint8_t *expected_data,
                               const char *operation)
{
    if (!expect_rc(read_result.rc, operation) ||
        read_result.bytes_read != BENCHMARK_FILE_SIZE) {
        microkit_debug_puts(TEST_VERBOSITY, "read size mismatch\n");
        return false;
    }

    if (!benchmark_buffers_equal(read_result.data_address, expected_data,
                                 BENCHMARK_FILE_SIZE)) {
        microkit_debug_puts(TEST_VERBOSITY, "readback mismatch\n");
        return false;
    }

    return true;
}

bool benchmark_prepare_root(uint8_t *fs_buffer_base, int channel_id,
                            const unsigned char *root_path)
{
    int rc = send_delete_entry_request(root_path, fs_buffer_base, channel_id);
    if (rc != FS_OK && rc != FS_ERR_NOT_FOUND) {
        return expect_rc(rc, "delete benchmark root");
    }

    rc = send_create_directory_request(root_path, PERM_PUBLIC, fs_buffer_base,
                                       channel_id);
    return expect_rc(rc, "create benchmark root");
}

bool benchmark_run_iterations(uint8_t *fs_buffer_base, int channel_id,
                              const unsigned char *root_path, uint32_t seed_base)
{
    unsigned char path[96];
    uint8_t write_buffer[BENCHMARK_FILE_SIZE];

    for (uint32_t iteration = 0; iteration < BENCHMARK_FILE_COUNT; iteration++) {
        benchmark_make_file_path(path, sizeof(path), root_path, iteration);
        benchmark_fill_pattern(write_buffer, sizeof(write_buffer),
                               seed_base + iteration * 17u);

        fs_result_fileid_t create_result = send_create_file_request(
            path, PERM_PUBLIC, READ_WRITE_OP, fs_buffer_base, channel_id);
        if (!expect_rc(create_result.rc, "create benchmark file")) {
            return false;
        }

        fs_result_write_t write_result = send_write_file_request(
            create_result.file_id, sizeof(write_buffer), write_buffer,
            fs_buffer_base, channel_id);
        if (!expect_rc(write_result.rc, "write benchmark file") ||
            write_result.bytes_written != sizeof(write_buffer)) {
            microkit_debug_puts(TEST_VERBOSITY, "write size mismatch\n");
            return false;
        }

        int rc = send_close_file_request(create_result.file_id, channel_id);
        if (!expect_rc(rc, "close benchmark file")) {
            return false;
        }

        fs_result_fileid_t open_result = send_open_file_request(
            READ_OP, path, fs_buffer_base, channel_id);
        if (!expect_rc(open_result.rc, "open benchmark file")) {
            return false;
        }

        fs_result_read_t first_read_result = send_read_file_request(
            open_result.file_id, sizeof(write_buffer), fs_buffer_base, channel_id);
        if (!expect_read_result(first_read_result, write_buffer,
                                "read benchmark file")) {
            return false;
        }

        rc = send_seek_file_request(open_result.file_id, 0, channel_id);
        if (!expect_rc(rc, "seek benchmark file")) {
            return false;
        }

        fs_result_read_t second_read_result = send_read_file_request(
            open_result.file_id, sizeof(write_buffer), fs_buffer_base, channel_id);
        if (!expect_read_result(second_read_result, write_buffer,
                                "read benchmark file after seek")) {
            return false;
        }

        rc = send_delete_entry_request(path, fs_buffer_base, channel_id);
        if (!expect_rc(rc, "delete benchmark file")) {
            return false;
        }
    }

    return true;
}

void benchmark_report_timing(const uint8_t label, uint64_t elapsed_ticks)
{
    uint64_t freq = read_cntfrq();
    uint64_t total_us = 0;
    uint64_t average_ticks = elapsed_ticks / BENCHMARK_FILE_COUNT;
    uint64_t average_us = 0;

    if (freq != 0) {
        total_us = (elapsed_ticks * 1000000u) / freq;
        average_us = total_us / BENCHMARK_FILE_COUNT;
    }

    // print from single point of high pri so no cutoff strings
	microkit_msginfo msginfo = microkit_msginfo_new(CLIENT_BENCHMARK_LABEL, 3);
	microkit_mr_set(0, label);
	microkit_mr_set(1, total_us);
	microkit_mr_set(2, average_us);
	microkit_ppcall(FILE_SERVER_CHANNEL_ID, msginfo);
}

void benchmark_finish(uint8_t *fs_buffer_base, int channel_id, bool success)
{
    if (!success) {
        microkit_debug_puts(TEST_VERBOSITY, "benchmark client failed\n");
    }

    mark_client_as_finished_running(fs_buffer_base);
    microkit_notify(channel_id);
    seL4_Yield();
}