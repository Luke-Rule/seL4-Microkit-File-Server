#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../debug_output.h"

#include "include/fs_shared.h"
#include "include/fs_queue_manager_server.h"

void increment_submission_queue_head(client_t *client) {
    size_t *submission_queue_head = &client->submission_queue_head;
    if (*submission_queue_head >= MAX_QUEUE_ENTRIES - 1) {
        *submission_queue_head = 0;
        return;
    }
    *submission_queue_head = *submission_queue_head + 1;
}

void add_completion_entry(client_t *client, const uint8_t return_code, const uint32_t parameter1,
                          const uint32_t parameter2, const size_t buffer_index) {
    if (client->completion_queue_tail + 1 == client->completion_queue_head ||
        (client->completion_queue_head == 1 && client->completion_queue_tail == MAX_QUEUE_ENTRIES - 1)) {
        microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: no free completion entries available\n");
        return;
    }

    completion_queue_entry_t *entry = &client->completion_queue[client->completion_queue_tail];
    entry->return_code = return_code;
    entry->parameter1 = parameter1;
    entry->parameter2 = parameter2;
    entry->buffer_index = buffer_index;

    if (client->completion_queue_tail >= MAX_QUEUE_ENTRIES - 1) {
        client->completion_queue_tail = 0;
        return;
    }
    client->completion_queue_tail = client->completion_queue_tail + 1;
}
