#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include "definitions.h"

#define FILE_SERVER_CHANNEL_ID 0

uintptr_t file_server_buffer_base;

void notified(microkit_channel client_id) {}

void debug_print_return_code(const char *operation, int return_code) {
    microkit_dbg_puts("CLIENT: ");
    microkit_dbg_puts(operation);
    microkit_dbg_puts(" operation returned code: ");
    switch (return_code)
    {
        case FS_OK:
            microkit_dbg_puts("FS_OK: Operation completed successfully.\n");
            break;
        case FS_ERR_TABLE_FULL:
            microkit_dbg_puts("FS_ERR_TABLE_FULL: The file table is full.\n");
            break;
        case FS_ERR_FILE_EXCEEDS_MAX_SIZE:
            microkit_dbg_puts("FS_ERR_FILE_EXCEEDS_MAX_SIZE: The file exceeds the maximum allowed size.\n");
            break;
        case FS_ERR_FILE_EXCEEDS_REMAINING_SPACE:
            microkit_dbg_puts("FS_ERR_FILE_EXCEEDS_REMAINING_SPACE: The file exceeds the remaining storage space.\n");
            break;
        case FS_ERR_INVALID_NAME:
            microkit_dbg_puts("FS_ERR_INVALID_NAME: The provided file name is invalid.\n");
            break;
        case FS_ERR_ALREADY_EXISTS:
            microkit_dbg_puts("FS_ERR_ALREADY_EXISTS: A file with the same name already exists.\n");
            break;
        case FS_ERR_NOT_FOUND:
            microkit_dbg_puts("FS_ERR_NOT_FOUND: The specified file was not found.\n");
            break;
        case FS_ERR_PERMISSION:
            microkit_dbg_puts("FS_ERR_PERMISSION: Permission denied for the requested operation.\n");
            break;
        case FS_ERR_OUT_OF_BOUNDS:
            microkit_dbg_puts("FS_ERR_OUT_OF_BOUNDS: The operation attempted to access data out of bounds.\n");
            break;
        case FS_ERR_NAME_COLLISION:
            microkit_dbg_puts("FS_ERR_NAME_COLLISION: A name collision occurred during the operation.\n");
            break;
        case FS_ERR_INVALID_OP_CODE:
            microkit_dbg_puts("FS_ERR_INVALID_OP_CODE: The provided operation code is invalid.\n");
            break;
        case FS_ERR_INCORRECT_OP_PARAM_COUNT:
            microkit_dbg_puts("FS_ERR_INCORRECT_OP_PARAM_COUNT: The number of operation parameters is incorrect.\n");
            break;
        case FS_ERR_UNSPECIFIED_ERROR:
            microkit_dbg_puts("FS_ERR_UNSPECIFIED_ERROR: An unspecified error occurred during the operation.\n");
            break;
        default:
            break;
    }
}


void init(void) {
    microkit_dbg_puts("CLIENT: started\n");

    microkit_msginfo msg = microkit_msginfo_new(0, 3);

    microkit_mr_set(0, OP_CREATE);
    const char *filename = "hello.txt\0";
    int file_name_counter = 0;
    while (file_name_counter < 256 && filename[file_name_counter] != '\0') {
        *((char *)(file_server_buffer_base + file_name_counter)) = filename[file_name_counter];
        file_name_counter++;
    }
    *((char *)(file_server_buffer_base + file_name_counter)) = '\0';
    microkit_mr_set(1, 11); // size
    microkit_mr_set(2, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE); // permissions

    microkit_dbg_puts("CLIENT: sent create request\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    int return_code = microkit_mr_get(0);
    debug_print_return_code("create", return_code);
}
