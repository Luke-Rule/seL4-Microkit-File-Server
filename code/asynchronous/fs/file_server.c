// ----------------------------------------------------------------------- //
// ------------------------ MicroKit File Server ------------------------- //
// ----------------------------------------------------------------------- //


// ------------------------------ Includes ------------------------------- //

#include <microkit.h>
#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_internal.h"
#include "fs_shared.h"
#include "fs_utils.h"
#include "fs_buffer_manager.h"
#include "fs_queue_manager_server.h"
#include "fs_block_manager.h"
#include "fs_i_node_manager.h"
#include "fs_operations.h"

#ifndef BENCHMARKING
#define BENCHMARKING 0
#endif

// ------------------------------ Globals ------------------------------- //

uintptr_t fs_memory_base;
uintptr_t clients_memory_base;

uint8_t *block_table;
file_descriptor_t *file_descriptor_table;
i_node_t *i_node_table;
block_t *blocks;
client_t *clients;

uint64_t freq;
uint64_t start;
int benchmark_reported;

// ------------------------------ Benchmarking functions ------------------------------- //

static inline uint64_t read_cntvct(void)
{
    uint64_t val;
    asm volatile("isb sy" : : : "memory");
    asm volatile("mrs %0, cntpct_el0" : "=r"(val));
    return val;
}

static inline uint64_t read_cntfrq(void)
{
    uint64_t val;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(val));
    return val;
}

static void microkit_dbg_putu64(uint64_t x)
{
    char buf[21];
    unsigned i = 0;

    if (x == 0) {
        microkit_dbg_putc('0');
        return;
    }

    while (x > 0 && i < sizeof(buf)) {
        buf[i++] = '0' + (x % 10);
        x /= 10;
    }

    while (i > 0) {
        microkit_dbg_putc(buf[--i]);
    }
}

static void microkit_dbg_putu32_6(uint32_t x)
{
    /* Print exactly 6 digits with leading zeros. */
    char buf[6];
    for (int i = 5; i >= 0; i--) {
        buf[i] = '0' + (x % 10);
        x /= 10;
    }
    for (int i = 0; i < 6; i++) {
        microkit_dbg_putc(buf[i]);
    }
}

// ------------------------------ File server operation ------------------------------- //

void handle_operation(file_operation_t operation, submission_queue_entry_t *submission_entry, uint32_t client_id) {
    switch (operation) {
        case OP_CREATE_FILE: {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: CREATE FILE OPERATION\n");
            uint8_t permissions = (uint8_t)submission_entry->parameter1;
            uint8_t operations = (uint8_t)submission_entry->parameter2;
            unsigned char *path = (unsigned char *)&clients[client_id].submission_buffers[submission_entry->buffer_index];
            microkit_debug_puts(OUTPUT_VERBOSITY, "creating with path: ");
            microkit_debug_puts(OUTPUT_VERBOSITY, (char *)path);
            microkit_debug_putc(OUTPUT_VERBOSITY, '\n');
            i_node_result_t i_node = create_entry(path, ROOT_DIRECTORY_I_NODE_INDEX, permissions, client_id, CREATE_FILE);
            if (i_node.return_code == FS_OK) {
                microkit_debug_puts(OUTPUT_VERBOSITY, "opening created file\n");
                open_file_operation(client_id, operations, path);
            }
            break;
        }

        case OP_CREATE_DIRECTORY: {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: CREATE DIRECTORY OPERATION\n");
            uint8_t permissions = (uint8_t)submission_entry->parameter1;
            unsigned char *path = (unsigned char *)&clients[client_id].submission_buffers[submission_entry->buffer_index];
            microkit_debug_puts(OUTPUT_VERBOSITY, "creating with path: ");
            microkit_debug_puts(OUTPUT_VERBOSITY, (char *)path);
            microkit_debug_putc(OUTPUT_VERBOSITY, '\n');
            i_node_result_t i_node = create_entry(path, ROOT_DIRECTORY_I_NODE_INDEX, permissions, client_id, CREATE_DIRECTORY);
            break;
        }

        case OP_OPEN:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: OPEN OPERATION\n");
            uint8_t requested_operations = (uint8_t)submission_entry->parameter1;
            open_file_operation(
                client_id,
                requested_operations,
                (char *)&clients[client_id].submission_buffers[submission_entry->buffer_index]
            );
            break;


        case OP_CLOSE:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: CLOSE OPERATION\n");
            uint32_t file_id = (uint32_t)submission_entry->parameter1;
            close_file_operation(client_id, file_id);
            break;


        case OP_READ: {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: READ OPERATION\n");
            uint32_t file_id = (uint32_t)submission_entry->parameter1;
            size_t length = (size_t)submission_entry->parameter2;
            read_file_operation(client_id, file_id, length);
            break;
        }

        case OP_WRITE: {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: WRITE OPERATION\n");
            uint32_t file_id = (uint32_t)submission_entry->parameter1;
            size_t write_length = (size_t)submission_entry->parameter2;
            write_file_operation(client_id, file_id, write_length, submission_entry->buffer_index);
            break;
        }

        case OP_SEEK: {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: SEEK OPERATION\n");
            uint32_t file_id = (uint32_t)submission_entry->parameter1;
            uint32_t position = (uint32_t)submission_entry->parameter2;
            seek_file_operation(client_id, file_id, position);
            break;
        }

        case OP_DELETE: {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: DELETE OPERATION\n");
            delete_entry_operation(
                client_id,
                (unsigned char *)&clients[client_id].submission_buffers[submission_entry->buffer_index]
            );
            break;
        }
            
        case OP_SET_PERMISSIONS: {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: SET PERMISSIONS OPERATION\n");
            uint8_t new_permissions = (uint8_t)submission_entry->parameter1;
            set_entry_permissions_operation(client_id,
                new_permissions,
                (unsigned char *)&clients[client_id].submission_buffers[submission_entry->buffer_index]
            );
            break;
        }

        case OP_GET_PERMISSIONS: {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: GET PERMISSIONS OPERATION\n");
            get_entry_permissions_operation(
                client_id,
                (unsigned char *)&clients[client_id].submission_buffers[submission_entry->buffer_index]
            );
            break;
        }

        case OP_GET_SIZE: {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: GET SIZE OPERATION\n");
            get_entry_size_operation(
                client_id,
                (unsigned char *)&clients[client_id].submission_buffers[submission_entry->buffer_index]
            );
            break;
        }

        case OP_EXISTS: {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: EXISTS OPERATION\n");
            entry_exists_operation(
                client_id,
                (unsigned char *)&clients[client_id].submission_buffers[submission_entry->buffer_index]
            );
            break;
        }

        case OP_LIST: {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: LIST OPERATION\n");
            list_directory_operation(
                client_id,
                (unsigned char *)&clients[client_id].submission_buffers[submission_entry->buffer_index]
            );
            break;
        }

        default:
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: INVALID OPERATION CODE\n");
            break;
    }
}

void service_client(uint32_t client_id) {
    uint32_t num_operations = 0;
    int unset_ready_flag = 0;
    // TODO: should prioritise operations, not really as OOO complications
    while (num_operations < MAX_OPERATIONS_PER_CLIENT_SERVICE) {
        microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: servicing client: ");
        microkit_debug_put32(OUTPUT_VERBOSITY, client_id);
        microkit_debug_putc(OUTPUT_VERBOSITY, '\n');

        if (clients[client_id].submission_queue_head == clients[client_id].submission_queue_tail) {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: no submission entries\n");
            unset_ready_flag = 1;
            break;
        }

        if (clients[client_id].completion_queue_tail + 1 == clients[client_id].completion_queue_head || 
                (clients[client_id].completion_queue_head == 1 &&
                 clients[client_id].completion_queue_tail == MAX_QUEUE_ENTRIES - 1)
           ) {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: no free completion entries\n");
            break;
        }

        submission_queue_entry_t *submission_entry = &clients[client_id].submission_queue[
            clients[client_id].submission_queue_head
        ];

        file_operation_t operation = (file_operation_t)submission_entry->operation_code;

        if (operation_requires_completion_buffer(operation) && !is_free_completion_buffer(client_id)) {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: no free completion buffer for operation\n");
            break;
        }
        
        handle_operation(operation, submission_entry, client_id);

        if (operation_requires_submission_buffer(operation)) {
            set_free_submission_buffer(client_id, submission_entry->buffer_index);
        }

        increment_submission_queue_head(client_id);
        num_operations++;
    }

    if (unset_ready_flag) {
        clients[client_id].flags.ready_flag = 0;
    }
    if (num_operations > 0) {
        clients[client_id].flags.complete_flag = 1;
    }
}

// this is only required if the fs is pre-empted and a different client submits a request
// this is reasonably unlikely so doesnt require fairness counting
void poll_clients() {
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        // to not service client that already reached max / hasnt read queue
        if (clients[i].flags.ready_flag && !clients[i].flags.complete_flag) {
            microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: client ");
            microkit_debug_put32(OUTPUT_VERBOSITY, i);
            microkit_debug_puts(OUTPUT_VERBOSITY, " had lost notif, servicing now.\n");
            service_client(i);
        }
    }
}

void check_end_of_benchmark() {
    if (benchmark_reported) {
        return;
    }
    for (int i = 0; i < NUMBER_OF_CLIENTS; i++) {
        if (!clients[i].flags.finished_running_flag) {
            return;
        }
    }
    uint64_t end = read_cntvct();
    uint64_t delta_ticks = end - start;

    uint64_t whole_s = 0;
    uint32_t frac_us = 0;
    if (freq != 0) {
        whole_s = delta_ticks / freq;
        uint64_t rem = delta_ticks % freq;
        frac_us = (uint32_t)((rem * 1000000u) / freq);
    }

    microkit_dbg_puts("Benchmark took: ");
    microkit_dbg_putu64(whole_s);
    microkit_dbg_putc('.');
    microkit_dbg_putu32_6(frac_us);
    microkit_dbg_puts(" s (");
    microkit_dbg_putu64(delta_ticks);
    microkit_dbg_puts(" ticks @ ");
    microkit_dbg_putu64(freq);
    microkit_dbg_puts(" Hz)\n");

    benchmark_reported = 1;
    seL4_Yield();
}

void service_and_poll(uint8_t client_id) {
    if (BENCHMARKING) {
        check_end_of_benchmark();
    }
    service_client(client_id);
    poll_clients();
}

// ------------------------- MicroKit Interface -------------------------- //

void init(void) {
    microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: started\n");
    block_table = (uint8_t *)fs_memory_base;
    i_node_table = (i_node_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS);
    file_descriptor_table = (file_descriptor_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS + sizeof(i_node_t) * MAX_NUMBER_OF_INODES);
    blocks = (block_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS + sizeof(i_node_t) * MAX_NUMBER_OF_INODES + sizeof(file_descriptor_t) * NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT);
    clients = (client_t *)clients_memory_base;

    microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: initialising block table\n");
    for (size_t i = 0; i < MAX_NUMBER_OF_BLOCKS; i++) {
        block_table[i] = 0;
    }
    microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: initialising inode table\n");
    for (size_t i = 0; i < MAX_NUMBER_OF_INODES; i++) {
        i_node_table[i].mode = 0;
    }
    microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: initialising fd table\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT; i++) {
        file_descriptor_table[i].i_node_index = -1;
    }
    microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: initialising client queues\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        clients[i].submission_queue_head = 0;
        clients[i].submission_queue_tail = 0;
        clients[i].completion_queue_head = 0;
        clients[i].completion_queue_tail = 0;
    }

    microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: initialising buffer table\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        for (size_t j = 0; j < NUMBER_OF_BUFFERS_PER_CLIENT; j++) {
            clients[i].submission_buffer_table[j] = 0;
            clients[i].completion_buffer_table[j] = 0;
        }
    }

    microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: allocating root block\n");
    block_id_result_t initial_i_node_block = allocate_block();

    zero_block(blocks[initial_i_node_block.index].data);

    microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: initialising root block\n");
    i_node_t *root_i_node = &i_node_table[allocate_i_node().index];
    root_i_node->mode = IN_USE_BIT_SET | IS_DIRECTORY_BIT_SET | (PERM_EXECUTE | PERM_READ) << PERMISSION_BITS_START; // not deleted, in use, dir, permissions
    root_i_node->owner_id = -1; // owned by file server
    root_i_node->block_indices[0] = initial_i_node_block.index;
    root_i_node->entry_size = 0;
    root_i_node->blocks_used = 1;

    freq = read_cntfrq();
    start = read_cntvct();
    benchmark_reported = 0;
}


microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo) {
    service_and_poll(ch);
    return msginfo;
}


void notified(microkit_channel ch) {
    service_and_poll(ch);
}