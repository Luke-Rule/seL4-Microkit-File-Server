#include <microkit.h>
#include <stdint.h>
#include <stddef.h>

#include "../../debug_output.h"

#include "include/fs_shared.h"

// ------------------------------ Client ------------------------------- //

void increment_queue_pointer(size_t *pointer) {
    if (*pointer >= MAX_QUEUE_ENTRIES - 1) {
        *pointer = 0;
        return;
    }
    *pointer = (*pointer + 1);
}

void add_submission_entry(const operation_t operation_code, const uint32_t parameter1, const uint32_t parameter2,
                      client_t *client_data, const size_t buffer_index) {
    
    if (client_data->submission_queue_tail + 1 == client_data->submission_queue_head ||
         (client_data->submission_queue_head == 0 && client_data->submission_queue_tail == MAX_QUEUE_ENTRIES - 1)) {
        return;
    }

    submission_queue_entry_t *new_entry = &client_data->submission_queue[client_data->submission_queue_tail];
    new_entry->operation_code = operation_code;
    new_entry->parameter1 = parameter1;
    new_entry->parameter2 = parameter2;
    new_entry->buffer_index = buffer_index;
    
    // must happen in this order to ensure the server doesn't see an incomplete entry
    increment_queue_pointer(&client_data->submission_queue_tail);
}

