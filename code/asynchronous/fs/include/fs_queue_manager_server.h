#pragma once
#include <stdint.h>
#include <stddef.h>

#include "fs_internal.h"
#include "fs_shared.h"

void increment_submission_queue_head(client_t *client);

void add_completion_entry(client_t *client, const uint8_t return_code, const uint32_t parameter1,
						  const uint32_t parameter2, const size_t buffer_index);