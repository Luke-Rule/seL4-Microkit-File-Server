#pragma once
#include <stdint.h>
#include <stddef.h>
#include "fs_buffer_manager.h"
#include "fs_shared.h"

void increment_submission_queue_tail(size_t *submission_queue_tail);
void increment_completion_queue_head(size_t *completion_queue_head);

void add_submission_entry(const file_operation_t operation_code, const uint32_t parameter1, const uint32_t parameter2,
						  client_t *client_data, const size_t buffer_index);
