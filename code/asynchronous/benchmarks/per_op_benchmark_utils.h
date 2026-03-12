#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "../fs/include/fs_shared.h"

#define PER_OP_BENCHMARK_FILE_COUNT 400
#define PER_OP_BENCHMARK_FILE_SIZE 2048
#define PER_OP_BENCHMARK_MAX_BATCH_SIZE 10

bool per_op_benchmark_run_workload(client_t *client_data, const unsigned char *root_path,
                                   uint32_t seed_base);
void per_op_benchmark_finish(client_t *client_data, bool success);