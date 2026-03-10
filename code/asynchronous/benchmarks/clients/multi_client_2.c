#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../../debug_output.h"

#include "../benchmark_utils.h"

uintptr_t fs_data_base;

void notified(microkit_channel ch)
{
	(void)ch;
}

void init(void)
{
	client_t *client_data = (client_t *)fs_data_base;

	microkit_debug_puts(TEST_VERBOSITY, "multi benchmark client 2 started\n");
	bool success = benchmark_run_workload(client_data,
									 (const unsigned char *)"/bench_mc2",
									 30u);
	microkit_debug_puts(TEST_VERBOSITY, "multi benchmark client 2 finished\n");

	benchmark_finish(client_data, success);
}
