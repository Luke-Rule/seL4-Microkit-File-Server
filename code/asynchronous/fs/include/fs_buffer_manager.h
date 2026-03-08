#pragma once

#include <stdint.h>
#include <stddef.h>

#include "fs_shared.h"

struct buffer_copy_result {
    uint8_t buffer_index;
    fs_result_t rc;
} typedef buffer_copy_result_t;

int get_free_buffer(uint8_t *buffer_table);
void set_free_buffer(int buffer_index, uint8_t *buffer_table);

buffer_copy_result_t copy_string_to_submission_buffer(const unsigned char *src, client_t *client_data);
buffer_copy_result_t copy_data_to_submission_buffer(const uint8_t *src, size_t length, client_t *client_data);