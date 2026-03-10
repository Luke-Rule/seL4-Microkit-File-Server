#pragma once

#include <stdint.h>
#include <stddef.h>

#include "fs_shared.h"

struct buffer_copy_result {
    size_t buffer_index;
    fs_result_t rc;
} typedef buffer_copy_result_t;

bool operation_requires_completion_buffer(const operation_t operation);
bool operation_requires_submission_buffer(const operation_t operation);

size_t get_free_buffer(bool *buffer_table);
void set_free_buffer(const size_t buffer_index, bool *buffer_table);
bool is_free_buffer(bool *buffer_table);

buffer_copy_result_t copy_string_to_submission_buffer(const unsigned char *src, client_t *client_data);
buffer_copy_result_t copy_data_to_submission_buffer(const uint8_t *src, size_t length, client_t *client_data);