#pragma once

#include <stddef.h>
#include <stdint.h>

#include "fs_api.h"

#define BENCHMARK_FILE_COUNT 8048
#define BENCHMARK_FILE_SIZE 2048

int benchmark_run_workload(uint8_t *fs_buffer_base, int channel_id,
                           const unsigned char *root_path, uint32_t seed_base);
void benchmark_finish(uint8_t *fs_buffer_base, int channel_id, int success);