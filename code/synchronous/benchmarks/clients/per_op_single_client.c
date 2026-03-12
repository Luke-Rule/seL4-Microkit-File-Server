#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../../debug_output.h"

#include "../per_op_benchmark_utils.h"

uintptr_t fs_data_base;

void notified(microkit_channel)
{
}

void init(void)
{
    uint8_t *fs_buffer_base = (uint8_t *)fs_data_base;

    microkit_debug_puts(TEST_VERBOSITY, "per-op single benchmark client started\n");
    bool success = per_op_benchmark_run_workload(
        fs_buffer_base,
        FILE_SERVER_CHANNEL_ID,
        (const unsigned char *)"/bench_per_op_single",
        1u);
    microkit_debug_puts(TEST_VERBOSITY, "per-op single benchmark client finished\n");

    per_op_benchmark_finish(fs_buffer_base, FILE_SERVER_CHANNEL_ID, success);
}