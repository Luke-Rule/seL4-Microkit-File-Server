#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../debug_output.h"
#include "../../timing_helpers.h"

#include "benchmark_shared.h"
#include "per_op_benchmark_utils.h"
#include "../fs/include/fs_api.h"

static uint32_t benchmark_file_ids[PER_OP_BENCHMARK_FILE_COUNT];
static uint8_t benchmark_file_data[PER_OP_BENCHMARK_FILE_COUNT][PER_OP_BENCHMARK_FILE_SIZE];

static bool expect_queue_rc(const fs_result_t rc, const char *operation)
{
    if (rc == FS_OK) {
        return true;
    }

    microkit_debug_puts(TEST_VERBOSITY, operation);
    microkit_debug_puts(TEST_VERBOSITY, " queue failed with rc=");
    microkit_debug_put32(TEST_VERBOSITY, (uint32_t)rc);
    microkit_debug_puts(TEST_VERBOSITY, "\n");
    return false;
}

static bool expect_completion_rc(const uint8_t rc, const char *operation)
{
    if (rc == FS_OK) {
        return true;
    }

    microkit_debug_puts(TEST_VERBOSITY, operation);
    microkit_debug_puts(TEST_VERBOSITY, " completion failed with rc=");
    microkit_debug_put32(TEST_VERBOSITY, rc);
    microkit_debug_puts(TEST_VERBOSITY, "\n");
    return false;
}

static bool expect_cleanup_completion_rc(const uint8_t rc, const char *operation)
{
    if (rc == FS_OK || rc == FS_ERR_NOT_FOUND) {
        return true;
    }

    return expect_completion_rc(rc, operation);
}

static bool get_completion_or_fail(client_t *client_data,
                                   completion_queue_entry_t *completion,
                                   const char *operation)
{
    fs_result_t rc = get_next_completion_entry(client_data, completion);
    if (rc == FS_OK) {
        return true;
    }

    microkit_debug_puts(TEST_VERBOSITY, operation);
    microkit_debug_puts(TEST_VERBOSITY, " had no completion rc=");
    microkit_debug_put32(TEST_VERBOSITY, (uint32_t)rc);
    microkit_debug_puts(TEST_VERBOSITY, "\n");
    return false;
}

static bool prepare_benchmark_root(client_t *client_data,
                                   const unsigned char *root_path)
{
    completion_queue_entry_t completion;

    if (!expect_queue_rc(send_delete_entry_request(root_path, client_data),
                         "delete per-op benchmark root") ||
        !expect_queue_rc(send_create_directory_request(root_path, PERM_PUBLIC,
                                                       client_data),
                         "create per-op benchmark root")) {
        return false;
    }

    notify_file_server_and_wait_for_all_operations(client_data, 2);

    if (!get_completion_or_fail(client_data, &completion,
                                "delete per-op benchmark root")) {
        return false;
    }

    if (completion.return_code != FS_OK && completion.return_code != FS_ERR_NOT_FOUND &&
        completion.return_code != FS_ERR_FILE_DESCRIPTOR_NOT_FOUND) {
        return expect_completion_rc(completion.return_code,
                                    "delete per-op benchmark root");
    }

    if (!get_completion_or_fail(client_data, &completion,
                                "create per-op benchmark root") ||
        !expect_completion_rc(completion.return_code,
                              "create per-op benchmark root")) {
        return false;
    }

    return true;
}

static bool queue_create_file(client_t *client_data, const unsigned char *path)
{
    return expect_queue_rc(
        send_create_file_request(path, PERM_PUBLIC, READ_WRITE_OP, client_data),
        "create per-op benchmark file");
}

static bool create_benchmark_files(client_t *client_data,
                                   const unsigned char *root_path,
                                   uint32_t *file_ids)
{
    unsigned char path[96];
    completion_queue_entry_t completion;

    for (uint32_t base = 0; base < PER_OP_BENCHMARK_FILE_COUNT;
         base += PER_OP_BENCHMARK_MAX_BATCH_SIZE) {
        uint32_t batch_count = PER_OP_BENCHMARK_FILE_COUNT - base;
        if (batch_count > PER_OP_BENCHMARK_MAX_BATCH_SIZE) {
            batch_count = PER_OP_BENCHMARK_MAX_BATCH_SIZE;
        }

        for (uint32_t offset = 0; offset < batch_count; offset++) {
            benchmark_make_file_path(path, sizeof(path), root_path, base + offset);
            if (!queue_create_file(client_data, path)) {
                return false;
            }
        }

        notify_file_server_and_wait_for_all_operations(client_data, batch_count);

        for (uint32_t offset = 0; offset < batch_count; offset++) {
            if (!get_completion_or_fail(client_data, &completion,
                                        "create per-op benchmark file") ||
                !expect_completion_rc(completion.return_code,
                                      "create per-op benchmark file")) {
                return false;
            }

            file_ids[base + offset] = completion.parameter1;
        }
    }

    return true;
}

static bool reset_file_cursors(client_t *client_data, const uint32_t *file_ids)
{
    completion_queue_entry_t completion;

    for (uint32_t base = 0; base < PER_OP_BENCHMARK_FILE_COUNT;
         base += PER_OP_BENCHMARK_MAX_BATCH_SIZE) {
        uint32_t batch_count = PER_OP_BENCHMARK_FILE_COUNT - base;
        if (batch_count > PER_OP_BENCHMARK_MAX_BATCH_SIZE) {
            batch_count = PER_OP_BENCHMARK_MAX_BATCH_SIZE;
        }

        for (uint32_t offset = 0; offset < batch_count; offset++) {
            if (!expect_queue_rc(send_seek_file_request(file_ids[base + offset], 0,
                                                       client_data),
                                 "seek per-op benchmark file")) {
                return false;
            }
        }

        notify_file_server_and_wait_for_all_operations(client_data, batch_count);

        for (uint32_t offset = 0; offset < batch_count; offset++) {
            if (!get_completion_or_fail(client_data, &completion,
                                        "seek per-op benchmark file") ||
                !expect_completion_rc(completion.return_code,
                                      "seek per-op benchmark file")) {
                return false;
            }
        }
    }

    return true;
}

static void print_phase_result(const char *phase, uint32_t batch_size,
                               uint64_t total_ticks)
{
    uint64_t freq = read_cntfrq();
    uint64_t average_ticks = total_ticks / PER_OP_BENCHMARK_FILE_COUNT;
    uint64_t average_us = 0;

    if (freq != 0) {
        average_us = (total_ticks * 1000000u) / freq / PER_OP_BENCHMARK_FILE_COUNT;
    }

    microkit_dbg_puts("per-op ");
    microkit_dbg_puts(phase);
    microkit_dbg_puts(" batch=");
    microkit_dbg_putu64(batch_size);
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

static bool run_write_phase(client_t *client_data, const uint32_t *file_ids,
                            uint32_t batch_size, uint64_t *elapsed_ticks)
{
    completion_queue_entry_t completion;
    *elapsed_ticks = 0;

    for (uint32_t base = 0; base < PER_OP_BENCHMARK_FILE_COUNT; base += batch_size) {
        uint32_t batch_count = PER_OP_BENCHMARK_FILE_COUNT - base;
        if (batch_count > batch_size) {
            batch_count = batch_size;
        }

        uint64_t start = read_cntvct();

        for (uint32_t offset = 0; offset < batch_count; offset++) {
            if (!expect_queue_rc(send_write_file_request(file_ids[base + offset],
                                                        PER_OP_BENCHMARK_FILE_SIZE,
                                                        benchmark_file_data[base + offset],
                                                        client_data),
                                 "write per-op benchmark file")) {
                return false;
            }
        }

        notify_file_server_and_wait_for_all_operations(client_data, batch_count);
        *elapsed_ticks += read_cntvct() - start;

        for (uint32_t offset = 0; offset < batch_count; offset++) {
            if (!get_completion_or_fail(client_data, &completion,
                                        "write per-op benchmark file")) {
                return false;
            }

            if (!expect_completion_rc(completion.return_code,
                                      "write per-op benchmark file")) {
                return false;
            }

            if (completion.parameter1 != PER_OP_BENCHMARK_FILE_SIZE) {
                microkit_debug_puts(TEST_VERBOSITY, "write size mismatch\n");
                return false;
            }
        }
    }

    return true;
}

static bool run_read_phase(client_t *client_data, const uint32_t *file_ids,
                           uint32_t batch_size, uint64_t *elapsed_ticks)
{
    completion_queue_entry_t completion;
    *elapsed_ticks = 0;

    for (uint32_t base = 0; base < PER_OP_BENCHMARK_FILE_COUNT; base += batch_size) {
        uint32_t batch_count = PER_OP_BENCHMARK_FILE_COUNT - base;
        if (batch_count > batch_size) {
            batch_count = batch_size;
        }

        uint64_t start = read_cntvct();

        for (uint32_t offset = 0; offset < batch_count; offset++) {
            if (!expect_queue_rc(send_read_file_request(file_ids[base + offset],
                                                       PER_OP_BENCHMARK_FILE_SIZE,
                                                       client_data),
                                 "read per-op benchmark file")) {
                return false;
            }
        }

        notify_file_server_and_wait_for_all_operations(client_data, batch_count);
        *elapsed_ticks += read_cntvct() - start;

        for (uint32_t offset = 0; offset < batch_count; offset++) {
            if (!get_completion_or_fail(client_data, &completion,
                                        "read per-op benchmark file")) {
                return false;
            }

            if (!expect_completion_rc(completion.return_code,
                                      "read per-op benchmark file")) {
                return false;
            }

            if (completion.parameter1 != PER_OP_BENCHMARK_FILE_SIZE) {
                microkit_debug_puts(TEST_VERBOSITY, "read size mismatch\n");
                set_free_completion_buffer(client_data, completion.buffer_index);
                return false;
            }

                if (!benchmark_buffers_equal(
                    client_data->completion_buffers[completion.buffer_index].data,
                    benchmark_file_data[base + offset],
                    PER_OP_BENCHMARK_FILE_SIZE)) {
                microkit_debug_puts(TEST_VERBOSITY, "readback mismatch\n");
                set_free_completion_buffer(client_data, completion.buffer_index);
                return false;
            }

            set_free_completion_buffer(client_data, completion.buffer_index);
        }
    }

    return true;
}

static bool close_benchmark_files(client_t *client_data, const uint32_t *file_ids)
{
    completion_queue_entry_t completion;

    for (uint32_t base = 0; base < PER_OP_BENCHMARK_FILE_COUNT;
         base += PER_OP_BENCHMARK_MAX_BATCH_SIZE) {
        uint32_t batch_count = PER_OP_BENCHMARK_FILE_COUNT - base;
        if (batch_count > PER_OP_BENCHMARK_MAX_BATCH_SIZE) {
            batch_count = PER_OP_BENCHMARK_MAX_BATCH_SIZE;
        }

        for (uint32_t offset = 0; offset < batch_count; offset++) {
            if (!expect_queue_rc(send_close_file_request(file_ids[base + offset],
                                                        client_data),
                                 "close per-op benchmark file")) {
                return false;
            }
        }

        notify_file_server_and_wait_for_all_operations(client_data, batch_count);

        for (uint32_t offset = 0; offset < batch_count; offset++) {
            if (!get_completion_or_fail(client_data, &completion,
                                        "close per-op benchmark file") ||
                !expect_completion_rc(completion.return_code,
                                      "close per-op benchmark file")) {
                return false;
            }
        }
    }

    return true;
}

static bool delete_benchmark_files(client_t *client_data,
                                   const unsigned char *root_path)
{
    unsigned char path[96];
    completion_queue_entry_t completion;

    for (uint32_t iteration = 0; iteration < PER_OP_BENCHMARK_FILE_COUNT; iteration++) {
        benchmark_make_file_path(path, sizeof(path), root_path, iteration);
        if (!expect_queue_rc(send_delete_entry_request(path, client_data),
                             "delete per-op benchmark file")) {
            return false;
        }

        notify_file_server_and_wait_for_all_operations(client_data, 1);

        if (!get_completion_or_fail(client_data, &completion,
                                    "delete per-op benchmark file") ||
            !expect_cleanup_completion_rc(completion.return_code,
                                          "delete per-op benchmark file")) {
            return false;
        }
    }

    if (!expect_queue_rc(send_delete_entry_request(root_path, client_data),
                         "delete per-op benchmark root")) {
        return false;
    }

    notify_file_server_and_wait_for_all_operations(client_data, 1);
    return get_completion_or_fail(client_data, &completion,
                                  "delete per-op benchmark root") &&
           expect_cleanup_completion_rc(completion.return_code,
                                        "delete per-op benchmark root");
}

bool per_op_benchmark_run_workload(client_t *client_data, const unsigned char *root_path,
                                   uint32_t seed_base)
{
    benchmark_clear_client_state(client_data);
    prepare_benchmark_data(seed_base);

    if (!prepare_benchmark_root(client_data, root_path) ||
        !create_benchmark_files(client_data, root_path, benchmark_file_ids)) {
        return false;
    }

    for (uint32_t batch_size = 1; batch_size <= PER_OP_BENCHMARK_MAX_BATCH_SIZE;
         batch_size++) {
        uint64_t write_ticks = 0;
        uint64_t read_ticks = 0;

        if (batch_size > 1 && !reset_file_cursors(client_data, benchmark_file_ids)) {
            return false;
        }

        if (!run_write_phase(client_data, benchmark_file_ids, batch_size, &write_ticks) ||
            !reset_file_cursors(client_data, benchmark_file_ids) ||
            !run_read_phase(client_data, benchmark_file_ids, batch_size, &read_ticks)) {
            return false;
        }

        print_phase_result("write", batch_size, write_ticks);
        print_phase_result("read", batch_size, read_ticks);
    }

    return close_benchmark_files(client_data, benchmark_file_ids) &&
           delete_benchmark_files(client_data, root_path);
}

void per_op_benchmark_finish(client_t *client_data, bool success)
{
    if (!success) {
        microkit_debug_puts(TEST_VERBOSITY, "per-op benchmark client failed\n");
    }

    mark_client_as_finished_running(client_data);
    microkit_notify(FILE_SERVER_CHANNEL_ID);
    seL4_Yield();
}