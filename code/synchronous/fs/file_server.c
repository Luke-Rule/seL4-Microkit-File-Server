// ----------------------------------------------------------------------- //
// ------------------------ MicroKit File Server ------------------------- //
// ----------------------------------------------------------------------- //


// ------------------------------ Includes ------------------------------- //

#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../debug_output.h"

#include "include/fs_shared.h"
#include "fs_internal.h"
#include "fs_utils.h"
#include "fs_block_manager.h"
#include "fs_i_node_manager.h"
#include "include/fs_operations.h"

#ifndef BENCHMARKING
#define BENCHMARKING 0
#endif

// ------------------------------ Globals ------------------------------- //

uintptr_t fs_memory_base;
uintptr_t clients_memory_base;

static fs_state_t fs_state;

uint64_t freq;
uint64_t start;
bool benchmark_reported;

static inline uint8_t *client_buffer_base(const uint8_t client_id)
{
    return (uint8_t *)(clients_memory_base + ((uintptr_t)client_id * CLIENT_BUFFER_SIZE));
}

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

microkit_msginfo protected(microkit_channel channel, microkit_msginfo msginfo) {
    if (microkit_msginfo_get_count(msginfo) < 1) {
        microkit_mr_set(0, FS_ERR_INVALID_OP_CODE);
        return msginfo;
    }

    const operation_t operation = microkit_mr_get(0);
    fs_result_t return_code = FS_ERR_UNSPECIFIED_ERROR;

    switch (operation) {
        case OP_CREATE_FILE: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            const permissions_t permissions = (permissions_t)microkit_mr_get(1);
            const file_open_operations_t operations = (file_open_operations_t)microkit_mr_get(2);
            const i_node_result_t i_node = create_entry(&fs_state, client_buffer_base(channel), ROOT_DIRECTORY_I_NODE_INDEX, permissions, channel, CREATE_FILE);
            if (i_node.return_code != FS_OK) {
                return_code = i_node.return_code;
            } else {
                fs_result_t fd_result = open_file_operation(&fs_state, channel, operations, client_buffer_base(channel));
                return_code = fd_result;
            }
            break;
        }

        case OP_CREATE_DIRECTORY: {
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            const permissions_t permissions = (permissions_t)microkit_mr_get(1);
            const i_node_result_t i_node = create_entry(&fs_state, client_buffer_base(channel), ROOT_DIRECTORY_I_NODE_INDEX, permissions, channel, CREATE_DIRECTORY);
            return_code = i_node.return_code;
            break;
        }

        case OP_OPEN:
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            const file_open_operations_t requested_operations = (file_open_operations_t)microkit_mr_get(1);
            return_code = open_file_operation(&fs_state, channel, requested_operations, client_buffer_base(channel));
            break;


        case OP_CLOSE:
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            const uint32_t file_id = microkit_mr_get(1);
            return_code = close_file_operation(&fs_state, channel, file_id);
            break;


        case OP_READ: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            const uint32_t file_id = microkit_mr_get(1);
            const size_t length = (size_t)microkit_mr_get(2);
            return_code = read_file_operation(&fs_state, channel, file_id, length, client_buffer_base(channel));
            break;
        }

        case OP_WRITE: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            const uint32_t file_id = microkit_mr_get(1);
            const size_t write_length = (size_t)microkit_mr_get(2);
            return_code = write_file_operation(&fs_state, channel, file_id, write_length, client_buffer_base(channel));
            break;
        }

        case OP_SEEK: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            const uint32_t file_id = microkit_mr_get(1);
            const size_t position = (size_t)microkit_mr_get(2);
            return_code = seek_file_operation(&fs_state, channel, file_id, position);
            break;
        }

        case OP_DELETE: {
            if (microkit_msginfo_get_count(msginfo) < 1) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            return_code = delete_entry_operation(&fs_state, channel, client_buffer_base(channel));
            break;
        }
            
        case OP_SET_PERMISSIONS: {
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            const permissions_t new_permissions = (permissions_t)microkit_mr_get(1);
            return_code = set_entry_permissions_operation(&fs_state, channel, new_permissions, client_buffer_base(channel));
            break;
        }

        case OP_GET_PERMISSIONS: {
            if (microkit_msginfo_get_count(msginfo) < 1) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            return_code = get_entry_permissions_operation(&fs_state, channel, client_buffer_base(channel));
            break;
        }

        case OP_GET_SIZE: {
            if (microkit_msginfo_get_count(msginfo) < 1) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            return_code = get_entry_size_operation(&fs_state, channel, client_buffer_base(channel));
            break;
        }

        case OP_EXISTS: {
            return_code = entry_exists_operation(&fs_state, channel, client_buffer_base(channel));
            break;
        }

        case OP_LIST: {
            return_code = list_directory_operation(&fs_state, channel, client_buffer_base(channel));
            break;
        }

        default:
            return_code = FS_ERR_INVALID_OP_CODE;
            break;
    }

    microkit_mr_set(0, return_code);

    return msginfo;
}

// ------------------------- MicroKit Interface -------------------------- //

void init(void) {
    microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: started\n");
    fs_state.block_table = (uint8_t *)fs_memory_base;
    fs_state.i_node_table = (i_node_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS);
    fs_state.file_descriptor_table = (file_descriptor_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS + sizeof(i_node_t) * MAX_NUMBER_OF_INODES);
    fs_state.blocks = (block_t *)(fs_memory_base + MAX_NUMBER_OF_BLOCKS + sizeof(i_node_t) * MAX_NUMBER_OF_INODES + sizeof(file_descriptor_t) * NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT);

    for (size_t i = 0; i < NUMBER_OF_CLIENTS * MAX_OPEN_FILES_PER_CLIENT; i++) {
        fs_state.file_descriptor_table[i].i_node_index = -1;
    }

    microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: allocating root block\n");
    block_id_result_t initial_i_node_block = allocate_block(&fs_state);

    zero_block(fs_state.blocks[initial_i_node_block.index].data);

    microkit_debug_puts(OUTPUT_VERBOSITY, "FILE SERVER: initialising root block\n");
    i_node_t *root_i_node = &fs_state.i_node_table[allocate_i_node(&fs_state).index];
    root_i_node->mode = IN_USE_BIT_SET | IS_DIRECTORY_BIT_SET | (PERM_EXECUTE | PERM_READ) << PERMISSION_BITS_START; // not deleted, in use, dir, permissions
    root_i_node->owner_id = -1; // owned by file server
    root_i_node->block_indices[0] = initial_i_node_block.index;
    root_i_node->entry_size = 0;
    root_i_node->blocks_used = 1;

    freq = read_cntfrq();
    start = read_cntvct();
    benchmark_reported = false;
}

void check_end_of_benchmark() {
    if (benchmark_reported) {
        return;
    }
    for (int i = 0; i < NUMBER_OF_CLIENTS; i++) {
        if (!client_buffer_base(i)[CLIENT_BUFFER_SIZE - 1]) {
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

    benchmark_reported = true;
    seL4_Yield();
}
void notified(microkit_channel) {
    if (BENCHMARKING) {
        check_end_of_benchmark();
    }
}