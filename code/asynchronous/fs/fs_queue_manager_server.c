#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../debug_output.h"

#include "include/fs_shared.h"
#include "include/fs_queue_manager_server.h"

void increment_queue_pointer(size_t *pointer) {
    if (*pointer >= MAX_QUEUE_ENTRIES - 1) {
        *pointer = 0;
        return;
    }
    *pointer = (*pointer + 1);
}

void add_completion_entry(client_t *client, const uint8_t return_code, const uint32_t parameter1,
                          const uint32_t parameter2, const size_t buffer_index) {

    if (client->completion_queue_tail + 1 == client->completion_queue_head ||
        (client->completion_queue_head == 0 && client->completion_queue_tail == MAX_QUEUE_ENTRIES - 1)) {
        return;
    }

    completion_queue_entry_t *entry = &client->completion_queue[client->completion_queue_tail];
    entry->return_code = return_code;
    entry->parameter1 = parameter1;
    entry->parameter2 = parameter2;
    entry->buffer_index = buffer_index;
    
    increment_queue_pointer(&client->completion_queue_tail);
}
