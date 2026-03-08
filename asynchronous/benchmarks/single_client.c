#include <microkit.h>
#include <stdint.h>

#include "debug_output.h"

#include "benchmark_utils.h"

uintptr_t fs_data_base;

void notified(microkit_channel ch)
{
	(void)ch;
}

void init(void)
{
	client_t *client_data = (client_t *)fs_data_base;

	microkit_debug_puts(TEST_VERBOSITY, "single benchmark client started\n");
	benchmark_finish(
		client_data,
		benchmark_run_workload(client_data, (const unsigned char *)"/bench_single",
							   1u));
}
