#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../debug_output.h"
#include "../../timing_helpers.h"

#include "benchmark_shared.h"
#include "per_op_benchmark_utils.h"

static uint8_t benchmark_file_data[PER_OP_BENCHMARK_FILE_COUNT][PER_OP_BENCHMARK_FILE_SIZE];

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

static void print_phase_result(const char *phase, uint64_t total_ticks,
                               uint32_t operation_count)
{
    uint64_t freq = read_cntfrq();
    uint64_t average_ticks = total_ticks / operation_count;
    uint64_t average_us = 0;

    if (freq != 0) {
        average_us = (total_ticks * 1000000u) / freq / operation_count;
    }

    microkit_dbg_puts("per-op ");
    microkit_dbg_puts(phase);
    microkit_dbg_puts(": total_ticks=");
    microkit_dbg_putu64(total_ticks);
    microkit_dbg_puts(", avg_ticks=");
    microkit_dbg_putu64(average_ticks);
    microkit_dbg_puts(", avg_us=");
    microkit_dbg_putu64(average_us);
    microkit_dbg_putc('\n');
}

static void prepare_benchmark_data(uint32_t seed_base)
{
    for (uint32_t iteration = 0; iteration < PER_OP_BENCHMARK_FILE_COUNT; iteration++) {
        benchmark_fill_pattern(benchmark_file_data[iteration],
                               PER_OP_BENCHMARK_FILE_SIZE,
                               seed_base + iteration * 17u);
    }
}

static bool prepare_benchmark_root(uint8_t *fs_buffer_base, int channel_id,
                                   const unsigned char *root_path)
{
    int rc = send_delete_entry_request(root_path, fs_buffer_base, channel_id);
    if (rc != FS_OK && rc != FS_ERR_NOT_FOUND) {
        return expect_rc(rc, "delete per-op benchmark root");
    }

    rc = send_create_directory_request(root_path, PERM_PUBLIC, fs_buffer_base,
                                       channel_id);
    return expect_rc(rc, "create per-op benchmark root");
}

static bool create_benchmark_files(uint8_t *fs_buffer_base, int channel_id,
                                   const unsigned char *root_path,
                                   uint32_t *file_ids)
{
    unsigned char path[96];

    for (uint32_t iteration = 0; iteration < PER_OP_BENCHMARK_FILE_COUNT; iteration++) {
        benchmark_make_file_path(path, sizeof(path), root_path, iteration);

        fs_result_fileid_t create_result = send_create_file_request(
            path, PERM_PUBLIC, READ_WRITE_OP, fs_buffer_base, channel_id);
        if (!expect_rc(create_result.rc, "create per-op benchmark file")) {
            return false;
        }

        file_ids[iteration] = create_result.file_id;
    }

    return true;
}

static bool write_benchmark_files(uint8_t *fs_buffer_base, int channel_id,
                                  const uint32_t *file_ids, uint64_t *elapsed_ticks)
{
    *elapsed_ticks = 0;

    for (uint32_t iteration = 0; iteration < PER_OP_BENCHMARK_FILE_COUNT; iteration++) {
        uint64_t start = read_cntvct();
        fs_result_write_t write_result = send_write_file_request(
            file_ids[iteration], PER_OP_BENCHMARK_FILE_SIZE,
            benchmark_file_data[iteration], fs_buffer_base,
            channel_id);
        *elapsed_ticks += read_cntvct() - start;

        if (!expect_rc(write_result.rc, "write per-op benchmark file")) {
            return false;
        }

        if (write_result.bytes_written != PER_OP_BENCHMARK_FILE_SIZE) {
            microkit_debug_puts(TEST_VERBOSITY, "write size mismatch\n");
            return false;
        }
    }

    return true;
}

static bool reset_benchmark_file_cursors(int channel_id, const uint32_t *file_ids)
{
    for (uint32_t iteration = 0; iteration < PER_OP_BENCHMARK_FILE_COUNT; iteration++) {
        if (!expect_rc(send_seek_file_request(file_ids[iteration], 0, channel_id),
                       "seek per-op benchmark file")) {
            return false;
        }
    }

    return true;
}

static bool read_benchmark_files(uint8_t *fs_buffer_base, int channel_id,
                                 const uint32_t *file_ids, uint64_t *elapsed_ticks)
{
    *elapsed_ticks = 0;

    for (uint32_t iteration = 0; iteration < PER_OP_BENCHMARK_FILE_COUNT; iteration++) {
        uint64_t start = read_cntvct();
        fs_result_read_t read_result = send_read_file_request(
            file_ids[iteration], PER_OP_BENCHMARK_FILE_SIZE, fs_buffer_base,
            channel_id);
        *elapsed_ticks += read_cntvct() - start;

        if (!expect_rc(read_result.rc, "read per-op benchmark file")) {
            return false;
        }

        if (read_result.bytes_read != PER_OP_BENCHMARK_FILE_SIZE) {
            microkit_debug_puts(TEST_VERBOSITY, "read size mismatch\n");
            return false;
        }

        if (!benchmark_buffers_equal(read_result.data_address,
                                     benchmark_file_data[iteration],
                                     PER_OP_BENCHMARK_FILE_SIZE)) {
            microkit_debug_puts(TEST_VERBOSITY, "readback mismatch\n");
            return false;
        }
    }

    return true;
}

static bool cleanup_benchmark_files(uint8_t *fs_buffer_base, int channel_id,
                                    const unsigned char *root_path,
                                    const uint32_t *file_ids)
{
    unsigned char path[96];

    for (uint32_t iteration = 0; iteration < PER_OP_BENCHMARK_FILE_COUNT; iteration++) {
        if (!expect_rc(send_close_file_request(file_ids[iteration], channel_id),
                       "close per-op benchmark file")) {
            return false;
        }
    }

    for (uint32_t iteration = 0; iteration < PER_OP_BENCHMARK_FILE_COUNT; iteration++) {
        benchmark_make_file_path(path, sizeof(path), root_path, iteration);
        if (!expect_rc(send_delete_entry_request(path, fs_buffer_base, channel_id),
                       "delete per-op benchmark file")) {
            return false;
        }
    }

    return expect_rc(send_delete_entry_request(root_path, fs_buffer_base, channel_id),
                     "delete per-op benchmark root");
}

bool per_op_benchmark_run_workload(uint8_t *fs_buffer_base, int channel_id,
                                   const unsigned char *root_path, uint32_t seed_base)
{
    uint32_t file_ids[PER_OP_BENCHMARK_FILE_COUNT];
    uint64_t write_ticks = 0;
    uint64_t read_ticks = 0;

    prepare_benchmark_data(seed_base);

    if (!prepare_benchmark_root(fs_buffer_base, channel_id, root_path) ||
        !create_benchmark_files(fs_buffer_base, channel_id, root_path, file_ids) ||
        !write_benchmark_files(fs_buffer_base, channel_id, file_ids, &write_ticks) ||
        !reset_benchmark_file_cursors(channel_id, file_ids) ||
        !read_benchmark_files(fs_buffer_base, channel_id, file_ids, &read_ticks)) {
        return false;
    }

    print_phase_result("write", write_ticks, PER_OP_BENCHMARK_FILE_COUNT);
    print_phase_result("read", read_ticks, PER_OP_BENCHMARK_FILE_COUNT);

    return cleanup_benchmark_files(fs_buffer_base, channel_id, root_path, file_ids);
}

void per_op_benchmark_finish(uint8_t *fs_buffer_base, int channel_id, bool success)
{
    if (!success) {
        microkit_debug_puts(TEST_VERBOSITY, "per-op benchmark client failed\n");
    }

    mark_client_as_finished_running(fs_buffer_base);
    microkit_notify(channel_id);
    seL4_Yield();
}