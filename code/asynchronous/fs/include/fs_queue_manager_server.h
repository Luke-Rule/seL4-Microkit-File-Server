#pragma once
#include <stdint.h>
#include <stddef.h>
#include "fs_buffer_manager.h"
#include "fs_shared.h"

size_t get_free_completion_buffer(const uint8_t client_id);
bool is_free_completion_buffer(const uint8_t client_id);

void increment_submission_queue_head(const uint8_t client_id);
void set_free_submission_buffer(const uint8_t client_id, const size_t buffer_index);

void add_completion_entry(const uint8_t client_id, const uint8_t return_code, const uint32_t parameter1,
						  const uint32_t parameter2, const size_t buffer_index);