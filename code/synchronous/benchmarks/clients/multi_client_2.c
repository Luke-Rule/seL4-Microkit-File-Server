#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../../debug_output.h"
#include "../../../timing_helpers.h"

#include "../benchmark_utils.h"

uintptr_t fs_data_base;

void notified(microkit_channel) {
}

void init(void) {
    uint8_t *fs_buffer_base = (uint8_t *)fs_data_base;
    uint64_t elapsed_ticks = 0;

    microkit_debug_puts(TEST_VERBOSITY, "2 started\n");
    bool success = benchmark_prepare_root(
        fs_buffer_base,
        FILE_SERVER_CHANNEL_ID,
        (const unsigned char *)"/bench_mc2");
    if (success) {
        uint64_t start_ticks = read_cntvct();
        success = benchmark_run_iterations(
            fs_buffer_base,
            FILE_SERVER_CHANNEL_ID,
            (const unsigned char *)"/bench_mc2",
            30u);
        elapsed_ticks = read_cntvct() - start_ticks;
        if (success) {
            benchmark_report_timing(2, elapsed_ticks);
        }
    }
    

    benchmark_finish(fs_buffer_base, FILE_SERVER_CHANNEL_ID, success);
}
