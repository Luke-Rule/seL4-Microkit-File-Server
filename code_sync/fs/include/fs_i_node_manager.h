
#pragma once

#include <stdint.h>

#include "fs_internal.h"
#include "fs_shared.h"

i_node_result_t allocate_i_node(void);
void release_i_node(uint32_t i_node_index);

i_node_result_t get_i_node_index(unsigned char *path, uint32_t parent_i_node_index, uint8_t client_id,
								 int get_parent);
