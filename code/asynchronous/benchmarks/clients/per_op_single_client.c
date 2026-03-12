#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../../debug_output.h"

#include "../per_op_benchmark_utils.h"

uintptr_t fs_data_base;

void notified(microkit_channel ch)
{
    (void)ch;
}

void init(void)
{
    client_t *client_data = (client_t *)fs_data_base;

    microkit_debug_puts(TEST_VERBOSITY, "per-op single benchmark client started\n");
    bool success = per_op_benchmark_run_workload(
        client_data,
        (const unsigned char *)"/bench_per_op_single",
        1u);
    microkit_debug_puts(TEST_VERBOSITY, "per-op single benchmark client finished\n");

    per_op_benchmark_finish(client_data, success);
}