#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "../fs/include/fs_api.h"

#define BENCHMARK_FILE_COUNT 2000
#define BENCHMARK_FILE_SIZE 2048

bool benchmark_run_workload(uint8_t *fs_buffer_base, int channel_id,
                           const unsigned char *root_path, uint32_t seed_base);
void benchmark_finish(uint8_t *fs_buffer_base, int channel_id, bool success);