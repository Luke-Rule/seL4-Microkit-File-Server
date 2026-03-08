#include <microkit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../debug_output.h"

#include "include/fs_shared.h"
#include "include/fs_queue_manager_server.h"
#include "include/fs_state.h"

static void increment_completion_queue_tail(size_t *completion_queue_tail) {
    if (*completion_queue_tail >= MAX_QUEUE_ENTRIES - 1) {
        *completion_queue_tail = 0;
        return;
    }
    *completion_queue_tail = (*completion_queue_tail + 1);
}

bool is_free_completion_buffer(const uint8_t client_id) {
    bool *table = clients[client_id].completion_buffer_table;
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        if (table[i] == false) {
            return true;
        }
    }
    return false;
}

size_t get_free_completion_buffer(const uint8_t client_id) {
    bool *table = clients[client_id].completion_buffer_table;
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        if (table[i] == false) {
            table[i] = true;
            return i;
        }
    }
    return SIZE_MAX;
}

void increment_submission_queue_head(const uint8_t client_id) {
    size_t *submission_queue_head = &clients[client_id].submission_queue_head;
    if (*submission_queue_head >= MAX_QUEUE_ENTRIES - 1) {
        *submission_queue_head = 0;
        return;
    }
    *submission_queue_head = (*submission_queue_head + 1);
}

void set_free_submission_buffer(const uint8_t client_id, const size_t buffer_index) {
    if (buffer_index >= NUMBER_OF_BUFFERS_PER_CLIENT) {
        return;
    }
    clients[client_id].submission_buffer_table[buffer_index] = false;
}

void add_completion_entry(const uint8_t client_id, const uint8_t return_code, const uint32_t parameter1,
                          const uint32_t parameter2, const size_t buffer_index) {
    client_t *client = &clients[client_id];
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

    increment_completion_queue_tail(&client->completion_queue_tail);
}
