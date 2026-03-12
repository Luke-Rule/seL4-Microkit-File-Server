#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../fs/include/fs_api.h"

void benchmark_make_file_path(unsigned char *dest, size_t capacity,
                              const unsigned char *root_path, uint32_t iteration);
void benchmark_copy_path(unsigned char *dest, size_t capacity,
                         const unsigned char *src);
void benchmark_fill_pattern(uint8_t *buffer, size_t length, uint32_t seed);
bool benchmark_buffers_equal(const uint8_t *lhs, const uint8_t *rhs, size_t length);
void benchmark_clear_client_state(client_t *client_data);