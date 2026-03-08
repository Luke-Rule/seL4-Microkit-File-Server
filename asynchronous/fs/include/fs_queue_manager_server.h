#pragma once
#include <stdint.h>
#include <stddef.h>
#include "fs_buffer_manager.h"
#include "fs_shared.h"

int get_free_completion_buffer(uint32_t client_id);
int is_free_completion_buffer(uint32_t client_id);

void increment_submission_queue_head(uint32_t client_id);
void set_free_submission_buffer(uint32_t client_id, int buffer_index);

void add_completion_entry(uint32_t client_id, uint8_t return_code, uint32_t parameter1,
						  uint32_t parameter2, int buffer_index);