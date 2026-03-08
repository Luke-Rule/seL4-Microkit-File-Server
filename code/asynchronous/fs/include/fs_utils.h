
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "fs_internal.h"
#include "fs_shared.h"

bool operation_requires_completion_buffer(const file_operation_t operation);
bool operation_requires_submission_buffer(const file_operation_t operation);

int32_t compare_names(const unsigned char *name1, const unsigned char *name2);
bool valid_name(const unsigned char *name);
bool valid_permissions(const i_node_t *i_node, const uint8_t client_id, const permissions_t required);

void copy_data_from_buffer(const uint8_t *src, uint8_t *dest, const size_t length);
size_t copy_string_from_buffer(const unsigned char *src, unsigned char *dest, const size_t max_length);
void zero_block(unsigned char *block);