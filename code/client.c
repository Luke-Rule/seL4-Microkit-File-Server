#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>

#include "debug_output.h"

#include "definitions.h"

#define FILE_SERVER_CHANNEL_ID 0

uintptr_t file_server_buffer_base;
uint8_t *fs_buffer_base;

void notified(microkit_channel client_id) {}

void init(void) {
    fs_buffer_base = (uint8_t *)file_server_buffer_base;
    microkit_dbg_puts("CLIENT: started\n");
}