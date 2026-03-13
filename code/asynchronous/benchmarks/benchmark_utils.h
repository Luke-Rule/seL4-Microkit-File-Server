#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "../fs/include/fs_shared.h"

#define BENCHMARK_FILE_COUNT 2048
#define BENCHMARK_FILE_SIZE 2048
#define BENCHMARK_MAX_BATCH_SIZE ((MAX_QUEUE_ENTRIES - 1) / 4)

bool benchmark_prepare_root(client_t *client_data, const unsigned char *root_path);
bool benchmark_run_iterations(client_t *client_data, const unsigned char *root_path,
					  uint32_t seed_base);
void benchmark_report_timing(const uint8_t label, uint64_t elapsed_ticks);
void benchmark_finish(client_t *client_data, bool success);
