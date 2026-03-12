#pragma once
#include <stdint.h>
#include <stddef.h>
#include "fs_shared.h"

void increment_queue_pointer(size_t *submission_queue_tail);

void add_submission_entry(const operation_t operation_code, const uint32_t parameter1, const uint32_t parameter2,
						  client_t *client_data, const size_t buffer_index);
