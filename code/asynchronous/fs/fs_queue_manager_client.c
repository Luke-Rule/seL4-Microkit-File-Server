#include <microkit.h>
#include <stdint.h>
#include <stddef.h>

#include "../debug_output.h"

#include "include/fs_api.h"
#include "include/fs_buffer_manager.h"
#include "include/fs_shared.h"

// ------------------------------ Client ------------------------------- //

void increment_submission_queue_tail(size_t *submission_queue_tail) {
    microkit_debug_puts(OUTPUT_VERBOSITY, "incrementing submission queue tail\n");
    if (*submission_queue_tail >= MAX_QUEUE_ENTRIES - 1) {
        // already checked theres space
        *submission_queue_tail = 1;
        return;
    }
    *submission_queue_tail = (*submission_queue_tail + 1);
}


void increment_completion_queue_head(size_t *completion_queue_head) {
    if (*completion_queue_head >= MAX_QUEUE_ENTRIES - 1) {
        *completion_queue_head = 1;
        return;
    }
    *completion_queue_head = (*completion_queue_head + 1);
}


void add_submission_entry(const file_operation_t operation_code, const uint32_t parameter1, const uint32_t parameter2,
                      client_t *client_data, const size_t buffer_index) {
    if (client_data->submission_queue_tail + 1 == client_data->submission_queue_head || (client_data->submission_queue_head == 1 && client_data->submission_queue_tail == MAX_QUEUE_ENTRIES - 1)) {
        microkit_debug_puts(OUTPUT_VERBOSITY, "CLIENT: no free submission entries available\n");
        return;
    }
    microkit_debug_puts(OUTPUT_VERBOSITY, "Adding submission entry at tail index: ");
    microkit_debug_put32(OUTPUT_VERBOSITY, client_data->submission_queue_tail);
    microkit_debug_putc(OUTPUT_VERBOSITY, '\n');
    submission_queue_entry_t new_entry;
    new_entry.operation_code = operation_code;
    new_entry.parameter1 = parameter1;
    new_entry.parameter2 = parameter2;
    new_entry.buffer_index = buffer_index;
    // crucial it happens in this order
    client_data->submission_queue[client_data->submission_queue_tail] = new_entry;
    increment_submission_queue_tail(&client_data->submission_queue_tail);
}

