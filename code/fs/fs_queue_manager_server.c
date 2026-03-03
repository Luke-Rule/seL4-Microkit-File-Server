#include <microkit.h>
#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_shared.h"
#include "fs_queue_manager_server.h"
#include "fs_state.h"

static void increment_completion_queue_tail(uint32_t *completion_queue_tail) {
    if (*completion_queue_tail >= MAX_QUEUE_ENTRIES - 1) {
        *completion_queue_tail = 0;
        return;
    }
    *completion_queue_tail = (*completion_queue_tail + 1);
}

int is_free_completion_buffer(uint32_t client_id) {
    uint8_t *table = clients[client_id].completion_buffer_table;
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        if (table[i] == 0) {
            return 1;
        }
    }
    return 0;
}

int get_free_completion_buffer(uint32_t client_id) {
    uint8_t *table = clients[client_id].completion_buffer_table;
    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        if (table[i] == 0) {
            table[i] = 1;
            return (int)i;
        }
    }
    return -1;
}

void increment_submission_queue_head(uint32_t client_id) {
    uint32_t *submission_queue_head = &clients[client_id].submission_queue_head;
    if (*submission_queue_head >= MAX_QUEUE_ENTRIES - 1) {
        *submission_queue_head = 0;
        return;
    }
    *submission_queue_head = (*submission_queue_head + 1);
}

void set_free_submission_buffer(uint32_t client_id, int buffer_index) {
    if (buffer_index < 0 || buffer_index >= NUMBER_OF_BUFFERS_PER_CLIENT) {
        return;
    }
    clients[client_id].submission_buffer_table[buffer_index] = 0;
}

void add_completion_entry(uint32_t client_id, uint8_t return_code, uint32_t parameter1,
                          uint32_t parameter2, int buffer_index) {
    client_t *client = &clients[client_id];
    if (client->completion_queue_tail + 1 == client->completion_queue_head ||
        (client->completion_queue_head == 1 && client->completion_queue_tail == MAX_QUEUE_ENTRIES - 1)) {
        microkit_dbg_puts("FILE SERVER: no free completion entries available\n");
        return;
    }

    completion_queue_entry_t *entry = &client->completion_queue[client->completion_queue_tail];
    entry->return_code = return_code;
    entry->parameter1 = parameter1;
    entry->parameter2 = parameter2;
    entry->buffer_index = (uint32_t)buffer_index;

    increment_completion_queue_tail(&client->completion_queue_tail);
}
