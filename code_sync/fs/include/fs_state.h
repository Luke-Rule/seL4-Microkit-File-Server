#pragma once

#include <stdint.h>

#include "fs_internal.h"
#include "fs_shared.h"

// These are owned/initialised by file_server.c
extern uintptr_t fs_memory_base;
extern uintptr_t clients_memory_base;

extern uint8_t *block_table;
extern file_descriptor_t *file_descriptor_table;
extern i_node_t *i_node_table;
extern block_t *blocks;
extern uint8_t *clients;

#define CLIENT_BUFFER_BASE(client_id) ((uintptr_t)clients + (uintptr_t)((client_id) * CLIENT_BUFFER_SIZE))
