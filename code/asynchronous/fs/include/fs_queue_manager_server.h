#pragma once
#include <stdint.h>
#include <stddef.h>

void increment_submission_queue_head(const uint8_t client_id);

void add_completion_entry(const uint8_t client_id, const uint8_t return_code, const uint32_t parameter1,
						  const uint32_t parameter2, const size_t buffer_index);