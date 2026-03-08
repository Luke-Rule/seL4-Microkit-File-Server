#pragma once
#include <stdint.h>
#include <stddef.h>
#include "fs_buffer_manager.h"
#include "fs_shared.h"

void increment_submission_queue_tail(uint32_t *submission_queue_tail);
void increment_completion_queue_head(uint32_t *completion_queue_head);

void add_submission_entry(uint8_t operation_code, uint32_t parameter1, uint32_t parameter2,
						  client_t *client_data, int buffer_index);
