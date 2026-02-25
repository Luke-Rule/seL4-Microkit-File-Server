// ----------------------------------------------------------------------- //
// ------------------------ MicroKit File Server ------------------------- //
// ----------------------------------------------------------------------- //


// ------------------------------ Includes ------------------------------- //

#include <microkit.h>
#include <stdint.h>
#include <stddef.h>
#include "fs_internal.h"
#include "fs_shared.h"
#include "fs_utils.h"
#include "fs_buffer_manager.h"
#include "fs_queue_manager_server.h"
#include "fs_block_manager.h"
#include "fs_i_node_manager.h"
#include "fs_operations.h"

// ------------------------------ Globals ------------------------------- //

uintptr_t fs_memory_base;
uintptr_t clients_memory_base;

uint8_t *block_table;
file_descriptor_t *file_descriptor_table;
i_node_t *i_node_table;
block_t *blocks;
client_t *clients;

void service_client(uint32_t client_id) {
    client_t *client = &clients[client_id];
    // TODO: limit number of operations per service to prevent starvation of other clients
    while (1) {
        microkit_dbg_puts("FILE SERVER: servicing client: ");
        microkit_dbg_put32(client_id);
        microkit_dbg_putc('\n');
        uint32_t submission_head = clients[client_id].submission_queue_head;
        uint32_t submission_tail = clients[client_id].submission_queue_tail;
        if (submission_head == submission_tail) {
            microkit_dbg_puts("FILE SERVER: no submission entries\n");
            break;
        }
        if (client->completion_queue_tail + 1 == client->completion_queue_head || (client->completion_queue_head == 1 && client->completion_queue_tail == MAX_QUEUE_ENTRIES - 1)) {
            microkit_dbg_puts("FILE SERVER: no free completion entries\n");
            break;
        }
        submission_queue_entry_t *submission_entry = &client->submission_queue[submission_head];
        uint32_t operation = submission_entry->operation_code;

        if ((operation == OP_READ || operation == OP_LIST) && !is_free_completion_buffer(client_id)) {
            microkit_dbg_puts("FILE SERVER: no free completion buffer for operation\n");
            break;
        }

        switch (operation) {
            case OP_CREATE_FILE: {
                microkit_dbg_puts("FILE SERVER: CREATE FILE OPERATION\n");
                uint8_t permissions = (uint8_t)submission_entry->parameter1;
                unsigned char *path = &client->submission_buffers[submission_entry->buffer_index].data[0];
                microkit_dbg_puts("creating with path: ");
                microkit_dbg_puts((char *)path);
                microkit_dbg_putc('\n');
                i_node_result_t i_node = create_entry(path, ROOT_DIRECTORY_I_NODE_INDEX, permissions, client_id, CREATE_FILE);
                if (i_node.return_code == FS_OK) {
                    microkit_dbg_puts("opening created file\n");
                    open_file_operation(client_id, permissions, path);
                }
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_CREATE_DIRECTORY: {
                microkit_dbg_puts("FILE SERVER: CREATE DIRECTORY OPERATION\n");
                uint8_t permissions = (uint8_t)submission_entry->parameter1;
                unsigned char *path = &client->submission_buffers[submission_entry->buffer_index].data[0];
                microkit_dbg_puts("creating with path: ");
                microkit_dbg_puts((char *)path);
                microkit_dbg_putc('\n');
                i_node_result_t i_node = create_entry(path, ROOT_DIRECTORY_I_NODE_INDEX, permissions, client_id, CREATE_DIRECTORY);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_OPEN:
                uint8_t requested_operations = (uint8_t)submission_entry->parameter1;
                open_file_operation(client_id, requested_operations, (char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;


            case OP_CLOSE:
                microkit_dbg_puts("FILE SERVER: CLOSE OPERATION\n");
                uint32_t file_id = (uint32_t)submission_entry->parameter1;
                close_file_operation(client_id, file_id);
                break;


            case OP_READ: {
                microkit_dbg_puts("FILE SERVER: READ OPERATION\n");
                uint32_t file_id = (uint32_t)submission_entry->parameter1;
                size_t length = (size_t)submission_entry->parameter2;
                read_file_operation(client_id, file_id, length);
                break;
            }

            case OP_WRITE: {
                microkit_dbg_puts("FILE SERVER: WRITE OPERATION\n");
                uint32_t file_id = (uint32_t)submission_entry->parameter1;
                size_t write_length = (size_t)submission_entry->parameter2;
                write_file_operation(client_id, file_id, write_length, submission_entry->buffer_index);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_SEEK: {
                microkit_dbg_puts("FILE SERVER: SEEK OPERATION\n");
                uint32_t file_id = (uint32_t)submission_entry->parameter1;
                uint32_t position = (uint32_t)submission_entry->parameter2;
                seek_file_operation(client_id, file_id, position);
                break;
            }

            case OP_DELETE: {
                microkit_dbg_puts("FILE SERVER: DELETE OPERATION\n");
                delete_entry_operation(client_id, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }
                
            case OP_SET_PERMISSIONS: {
                microkit_dbg_puts("FILE SERVER: SET PERMISSIONS OPERATION\n");
                uint8_t new_permissions = (uint8_t)submission_entry->parameter1;
                set_entry_permissions_operation(client_id, new_permissions, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_GET_PERMISSIONS: {
                microkit_dbg_puts("FILE SERVER: GET PERMISSIONS OPERATION\n");
                get_entry_permissions_operation(client_id, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_GET_SIZE: {
                microkit_dbg_puts("FILE SERVER: GET SIZE OPERATION\n");
                get_entry_size_operation(client_id, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_EXISTS: {
                microkit_dbg_puts("FILE SERVER: EXISTS OPERATION\n");
                entry_exists_operation(client_id, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            case OP_LIST: {
                microkit_dbg_puts("FILE SERVER: LIST OPERATION\n");
                list_directory_operation(client_id, (unsigned char *)&client->submission_buffers[submission_entry->buffer_index]);
                set_free_submission_buffer(client_id, submission_entry->buffer_index);
                break;
            }

            default:
                microkit_dbg_puts("FILE SERVER: INVALID OPERATION CODE\n");
                break;
        }

        increment_submission_queue_head(client_id);
    }

    clients[client_id].flags.ready_flag = 0;
    clients[client_id].flags.complete_flag = 1;
}


void poll_clients() {
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        if (clients[i].flags.ready_flag && !clients[i].flags.complete_flag) {
            microkit_dbg_puts("FILE SERVER: client ");
            microkit_dbg_put32(i);
            microkit_dbg_puts(" had lost notif, servicing now.\n");
            service_client(i);
        }
    }
}

// ------------------------- MicroKit Interface -------------------------- //

void init(void) {
    microkit_dbg_puts("FILE SERVER: started\n");
    block_table = (uint8_t *)fs_memory_base;
    i_node_table = (i_node_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS);
    file_descriptor_table = (file_descriptor_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS + sizeof(i_node_t) * MAX_NUMBER_OF_INODES);
    blocks = (block_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS + sizeof(i_node_t) * MAX_NUMBER_OF_INODES + sizeof(file_descriptor_t) * NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT);
    clients = (client_t *)clients_memory_base;

    microkit_dbg_puts("FILE SERVER: initialising block table\n");
    for (size_t i = 0; i < MAX_NUMBER_OF_BLOCKS; i++) {
        block_table[i] = 0;
    }
    microkit_dbg_puts("FILE SERVER: initialising inode table\n");
    for (size_t i = 0; i < MAX_NUMBER_OF_INODES; i++) {
        i_node_table[i].mode = 0;
    }
    microkit_dbg_puts("FILE SERVER: initialising fd table\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT; i++) {
        file_descriptor_table[i].i_node_index = -1;
    }
    microkit_dbg_puts("FILE SERVER: initialising client queues\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        clients[i].submission_queue_head = 0;
        clients[i].submission_queue_tail = 0;
        clients[i].completion_queue_head = 0;
        clients[i].completion_queue_tail = 0;
    }

    microkit_dbg_puts("FILE SERVER: initialising buffer table\n");
    for (size_t i = 0; i < NUMBER_OF_CLIENTS; i++) {
        for (size_t j = 0; j < NUMBER_OF_BUFFERS_PER_CLIENT; j++) {
            clients[i].submission_buffer_table[j] = 0;
            clients[i].completion_buffer_table[j] = 0;
        }
    }

    microkit_dbg_puts("FILE SERVER: allocating root block\n");
    block_id_result_t initial_i_node_block = allocate_block();

    microkit_dbg_puts("FILE SERVER: initialising root block\n");
    i_node_t *root_i_node = &i_node_table[allocate_i_node().index];
    root_i_node->mode = 0b00001 | 0b00010 | (PERM_EXECUTE || PERM_READ) << 2; // in use, dir, permissions
    root_i_node->owner_id = -1; // owned by file server
    root_i_node->block_indices[0] = initial_i_node_block.index;
    root_i_node->entry_size = 0;
    root_i_node->blocks_used = 1;
}


microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo) {
    service_client(ch);
    poll_clients();

    return msginfo;
}


void notified(microkit_channel ch) {
    service_client(ch);
    poll_clients();
}