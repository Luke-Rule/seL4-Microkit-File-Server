#pragma once
#include <stdint.h>
#include <stddef.h>

#include "fs_internal.h"

void increment_submission_queue_head(fs_state_t *state, const uint8_t client_id);

void add_completion_entry(fs_state_t *state, const uint8_t client_id, const uint8_t return_code,
						  const uint32_t parameter1, const uint32_t parameter2, const size_t buffer_index);