#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "../fs/include/fs_shared.h"

#define BENCHMARK_FILE_COUNT 2000
#define BENCHMARK_FILE_SIZE 2048

bool benchmark_run_workload(client_t *client_data, const unsigned char *root_path,
						   uint32_t seed_base);
void benchmark_finish(client_t *client_data, bool success);
