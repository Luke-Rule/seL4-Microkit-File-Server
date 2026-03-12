#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "../fs/include/fs_api.h"

#define PER_OP_BENCHMARK_FILE_COUNT 400
#define PER_OP_BENCHMARK_FILE_SIZE 2048

bool per_op_benchmark_run_workload(uint8_t *fs_buffer_base, int channel_id,
                                   const unsigned char *root_path, uint32_t seed_base);
void per_op_benchmark_finish(uint8_t *fs_buffer_base, int channel_id, bool success);