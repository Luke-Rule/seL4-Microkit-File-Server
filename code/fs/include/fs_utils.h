
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "fs_internal.h"
#include "fs_shared.h"

int operation_requires_completion_buffer(file_operation_t operation);
int operation_requires_submission_buffer(file_operation_t operation);

int32_t compare_names(const unsigned char *name1, const unsigned char *name2);
int valid_name(const unsigned char *name);
int valid_permissions(const i_node_t *i_node, uint8_t client_id, permissions_t required);

void copy_data_from_buffer(const uint8_t *src, uint8_t *dest, size_t length);
size_t copy_string_from_buffer(const unsigned char *src, unsigned char *dest, size_t max_length);
