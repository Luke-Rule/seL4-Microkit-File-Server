#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>

#include "../debug_output.h"

#include "benchmark_utils.h"

uintptr_t fs_data_base;

void notified(microkit_channel ch) {
    (void)ch;
}

void init(void) {
    uint8_t *fs_buffer_base = (uint8_t *)fs_data_base;

    microkit_debug_puts(TEST_VERBOSITY, "multi benchmark client 2 started\n");
    bool success = benchmark_run_workload(
        fs_buffer_base,
        FILE_SERVER_CHANNEL_ID,
        (const unsigned char *)"/bench_mc2",
        30u);
    microkit_debug_puts(TEST_VERBOSITY, "multi benchmark client 2 finished\n");

    benchmark_finish(fs_buffer_base, FILE_SERVER_CHANNEL_ID, success);
}