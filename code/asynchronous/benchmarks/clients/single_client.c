#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../../debug_output.h"
#include "../../../timing_helpers.h"

#include "../benchmark_utils.h"

uintptr_t fs_data_base;

void notified(microkit_channel ch)
{
    (void)ch;
}

void init(void)
{
    client_t *client_data = (client_t *)fs_data_base;
    uint64_t elapsed_ticks = 0;

    microkit_debug_puts(TEST_VERBOSITY, "single benchmark client started\n");
    bool success = benchmark_prepare_root(client_data,
                                          (const unsigned char *)"/bench_single");
    if (success) {
        uint64_t start_ticks = read_cntvct();
        success = benchmark_run_iterations(client_data,
                                           (const unsigned char *)"/bench_single",
                                           1u);
        elapsed_ticks = read_cntvct() - start_ticks;
        if (success) {
            benchmark_report_timing(single benchmark client, elapsed_ticks);
        }
    }
    microkit_debug_puts(TEST_VERBOSITY, "single benchmark client finished\n");

    benchmark_finish(client_data, success);
}
