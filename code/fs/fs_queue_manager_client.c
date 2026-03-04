#include <microkit.h>
#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_api.h"
#include "fs_buffer_manager.h"
#include "fs_shared.h"

// ------------------------------ Client ------------------------------- //

void increment_submission_queue_tail(uint32_t *submission_queue_tail) {
    microkit_debug_puts("incrementing submission queue tail\n");
    if (*submission_queue_tail >= MAX_QUEUE_ENTRIES - 1) {
        // already checked theres space
        *submission_queue_tail = 1;
        return;
    }
    *submission_queue_tail = (*submission_queue_tail + 1);
}


void increment_completion_queue_head(uint32_t *completion_queue_head) {
    if (*completion_queue_head >= MAX_QUEUE_ENTRIES - 1) {
        *completion_queue_head = 1;
        return;
    }
    *completion_queue_head = (*completion_queue_head + 1);
}


void add_submission_entry(uint8_t operation_code, uint32_t parameter1, uint32_t parameter2, client_t *client_data, const int buffer_index) {
    if (client_data->submission_queue_tail + 1 == client_data->submission_queue_head || (client_data->submission_queue_head == 1 && client_data->submission_queue_tail == MAX_QUEUE_ENTRIES - 1)) {
        microkit_debug_puts("CLIENT: no free submission entries available\n");
        return;
    }
    microkit_debug_puts("Adding submission entry at tail index: ");
    microkit_debug_put32(client_data->submission_queue_tail);
    microkit_debug_putc('\n');
    submission_queue_entry_t new_entry;
    new_entry.operation_code = operation_code;
    new_entry.parameter1 = parameter1;
    new_entry.parameter2 = parameter2;
    new_entry.buffer_index = buffer_index;
    client_data->submission_queue[client_data->submission_queue_tail] = new_entry;
    increment_submission_queue_tail(&client_data->submission_queue_tail);
}

