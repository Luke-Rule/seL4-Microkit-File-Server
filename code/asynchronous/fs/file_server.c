// ----------------------------------------------------------------------- //
// ------------------------ MicroKit File Server ------------------------- //
// ----------------------------------------------------------------------- //


// ------------------------------ Includes ------------------------------- //

#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../../debug_output.h"
#include "../../timing_helpers.h"

#include "include/fs_shared.h"
#include "fs_internal.h"
#include "fs_utils.h"
#include "include/fs_buffer_manager.h"
#include "include/fs_queue_manager_server.h"
#include "fs_block_manager.h"
#include "fs_i_node_manager.h"
#include "include/fs_operations.h"

// ------------------------------ Global state ------------------------------- //

// Microkit initialises these
uintptr_t fs_memory_base;
uintptr_t clients_memory_base;

static fs_state_t fs_state;
static client_t *clients;

// ------------------------------ File server operation ------------------------------- //

void handle_operation(fs_state_t *state, client_t *client, const operation_t operation,
                      const submission_queue_entry_t *submission_entry, const uint8_t client_id) {
    
    switch (operation) {
        case OP_CREATE_FILE: {
            const permissions_t permissions = (permissions_t)submission_entry->parameter1;
            const file_open_operations_t operations = (file_open_operations_t)submission_entry->parameter2;
            unsigned char *path = (unsigned char *)&client->submission_buffers[submission_entry->buffer_index];

            i_node_result_t i_node = create_entry(state, client, path, ROOT_DIRECTORY_I_NODE_INDEX,
                                                  permissions, client_id, CREATE_FILE);
            if (i_node.return_code == FS_OK) {
                open_file_operation(state, client, client_id, operations, path);
            }

            break;
        }

        case OP_CREATE_DIRECTORY: {
            const permissions_t permissions = (permissions_t)submission_entry->parameter1;
            unsigned char *path = (unsigned char *)&client->submission_buffers[submission_entry->buffer_index];

            create_entry(state, client, path, ROOT_DIRECTORY_I_NODE_INDEX, permissions, client_id,
                         CREATE_DIRECTORY);

            break;
        }

        case OP_OPEN:
            const file_open_operations_t requested_operations = (file_open_operations_t)submission_entry->parameter1;
            open_file_operation(
                state,
                client,
                client_id,
                requested_operations,
                (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]
            );

            break;


        case OP_CLOSE:
            uint32_t file_id = submission_entry->parameter1;
            close_file_operation(state, client, client_id, file_id);

            break;


        case OP_READ: {
            uint32_t file_id = submission_entry->parameter1;
            size_t length = (size_t)submission_entry->parameter2;
            
            read_file_operation(state, client, client_id, file_id, length);
            
            break;
        }

        case OP_WRITE: {
            uint32_t file_id = submission_entry->parameter1;
            size_t write_length = (size_t)submission_entry->parameter2;

            write_file_operation(state, client, client_id, file_id, write_length,
                                 submission_entry->buffer_index);
            break;
        }

        case OP_SEEK: {
            uint32_t file_id = submission_entry->parameter1;
            size_t position = (size_t)submission_entry->parameter2;

            seek_file_operation(state, client, client_id, file_id, position);

            break;
        }

        case OP_DELETE: {
            delete_entry_operation(
                state,
                client,
                client_id,
                (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]
            );

            break;
        }
            
        case OP_SET_PERMISSIONS: {
            const permissions_t new_permissions = (permissions_t)submission_entry->parameter1;
            set_entry_permissions_operation(state, client, client_id,
                new_permissions,
                (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]
            );

            break;
        }

        case OP_GET_PERMISSIONS: {
            get_entry_permissions_operation(
                state,
                client,
                client_id,
                (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]
            );

            break;
        }

        case OP_GET_SIZE: {
            get_entry_size_operation(
                state,
                client,
                client_id,
                (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]
            );
            break;
        }

        case OP_EXISTS: {
            entry_exists_operation(
                state,
                client,
                client_id,
                (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]
            );

            break;
        }

        case OP_LIST: {
            list_directory_operation(
                state,
                client,
                client_id,
                (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]
            );

            break;
        }

        default:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: INVALID OPERATION CODE\n");
            break;
    }
}

void service_client(fs_state_t *state, client_t *client, const uint8_t client_id) {
    size_t num_operations = 0;
    bool unset_ready_flag = 0;

    // Limit the number of operations to prevent a single client from starving others
    while (num_operations < MAX_OPERATIONS_PER_CLIENT_SERVICE) {
        // operations are accepted via a submission queue per client, each entry contains the op to be performed, 
        // alonside parameters and possible buffer index holding data to be written / path to be used
        if (client->submission_queue_head == client->submission_queue_tail) {
            // No more submissions to process
            unset_ready_flag = true;
            break;
        }
        
        // results from operations are returned in a similar way
        if (client->completion_queue_tail + 1 == client->completion_queue_head || 
                (client->completion_queue_head == 1 && client->completion_queue_tail == MAX_QUEUE_ENTRIES - 1)
           ) {
            // No more space in completion queue to write results
            break;
        }

        submission_queue_entry_t *submission_entry = &client->submission_queue[client->submission_queue_head];
        operation_t operation = (operation_t)submission_entry->operation_code;

        // if reading e.g.
        if (operation_requires_completion_buffer(operation) && !is_free_buffer(client->completion_buffer_table)) {
            break;
        }
        
        handle_operation(state, client, operation, submission_entry, client_id);

        // if was writing e.g. no longer require the data given by the client
        if (operation_requires_submission_buffer(operation)) {
            set_free_buffer(submission_entry->buffer_index, client->submission_buffer_table);
        }

        increment_queue_pointer(&client->submission_queue_head);
        num_operations++;
    }

    // only unready if we completed all their requests
    if (unset_ready_flag) {
        client->flags.ready_flag = false;
    }
    // even if not all of the client's operations were serviced, they may be able to use the results so far
    if (num_operations > 0) {
        client->flags.complete_flag = true;
    }
}

// while running on a single core, this is only required if the fs is pre-empted and a different client submits a request, 
// or the client is rate-limited, this isn't too common so doesnt require fairness counting
void poll_clients(void) {
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        // check complete not set to not service client that already reached max per service / hasnt read queue
        if (clients[i].flags.ready_flag && !clients[i].flags.complete_flag) {
            service_client(&fs_state, &clients[i], i);
        }
    }
}


void service_and_poll(const uint8_t client_id) {
    service_client(&fs_state, &clients[client_id], client_id);
    poll_clients();
}

// ------------------------- MicroKit Interface -------------------------- //

void init(void) {
    fs_state.block_table = (uint8_t *)fs_memory_base;
    fs_state.i_node_table = (i_node_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS);
    fs_state.file_descriptor_table = (file_descriptor_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS + sizeof(i_node_t) * MAX_NUMBER_OF_INODES);
    fs_state.blocks = (block_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS + sizeof(i_node_t) * MAX_NUMBER_OF_INODES + sizeof(file_descriptor_t) * NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT);
    clients = (client_t *)clients_memory_base;

    for (size_t i = 0; i < MAX_NUMBER_OF_BLOCKS; i++) {
        fs_state.block_table[i] = 0;
    }
    for (size_t i = 0; i < MAX_NUMBER_OF_INODES; i++) {
        fs_state.i_node_table[i].mode = 0;
    }
    for (size_t i = 0; i < NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT; i++) {
        fs_state.file_descriptor_table[i].i_node_index = -1;
    }
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        clients[i].submission_queue_head = 0;
        clients[i].submission_queue_tail = 0;
        clients[i].completion_queue_head = 0;
        clients[i].completion_queue_tail = 0;
    }
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        for (size_t j = 0; j < NUMBER_OF_BUFFERS_PER_CLIENT; j++) {
            clients[i].submission_buffer_table[j] = false;
            clients[i].completion_buffer_table[j] = false;
        }
    }

    block_id_result_t initial_i_node_block = allocate_block(&fs_state);

    zero_block(fs_state.blocks[initial_i_node_block.index].data);

    i_node_t *root_i_node = &fs_state.i_node_table[allocate_i_node(&fs_state).index];
    // dont allow deletion of root
    root_i_node->mode = IN_USE_BIT_SET | IS_DIRECTORY_BIT_SET | (PERM_EXECUTE | PERM_READ) << PERMISSION_BITS_START; // not deleted, in use, dir, permissions
    root_i_node->owner_id = -1; // owned by file server
    root_i_node->block_indices[0] = initial_i_node_block.index;
    root_i_node->entry_size = 0;
    root_i_node->blocks_used = 1;

}

void output_client_benchmark(const uint8_t client_id, const uint64_t total_us, const uint64_t average_us) {   
    seL4_Yield();
	microkit_dbg_put32(client_id);
	microkit_dbg_puts(", total=");
	microkit_dbg_putu64(total_us);
	microkit_dbg_puts(", avg=");
	microkit_dbg_putu64(average_us);
	microkit_dbg_putc('\n');
}

// blocking entry point to fs from client
microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo) {
    if (microkit_msginfo_get_label(msginfo) == CLIENT_BENCHMARK_LABEL) {
        output_client_benchmark(microkit_mr_get(0), microkit_mr_get(1), microkit_mr_get(2));
        return msginfo;
    }
    service_and_poll(ch);
    return msginfo;
}

// non-blocking entry point to fs from client
void notified(microkit_channel ch) {
    service_and_poll(ch);
}