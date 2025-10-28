#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>

#define FILE_SERVER_CHANNEL_ID 0

// File operations
#define CREATE 0
#define READ 1
#define WRITE 2
#define OPEN 3
#define CLOSE 4
#define DELETE 5
#define LIST 6
#define SET_PERMISSIONS 7
#define GET_PERMISSIONS 8
#define RENAME 9
#define GET_FILE_SIZE 10
#define EXISTS 11
#define COPY 12

// Responses
#define SUCCESS 0
#define FAILURE -1

uintptr_t file_server_buffer_base;

void notified(microkit_channel client_id) {}

void init(void) {
    microkit_dbg_puts("CLIENT: started\n");

    microkit_msginfo msg = microkit_msginfo_new(0, 1);

    microkit_mr_set(0, CREATE);
    const char *filename = "hello.txt\0";
    int file_name_counter = 0;
    while (file_name_counter < 256 && filename[file_name_counter] != '\0') {
        *((char *)(file_server_buffer_base + file_name_counter)) = filename[file_name_counter];
        file_name_counter++;
    }
    *((char *)(file_server_buffer_base + file_name_counter)) = '\0';

    microkit_dbg_puts("CLIENT: sent create request\n");
    microkit_ppcall(FILE_SERVER_CHANNEL_ID, msg);

    bool success = microkit_mr_get(0);
    if (success == 0) {
        microkit_dbg_puts("CLIENT: File created successfully\n");
    } else {
        microkit_dbg_puts("CLIENT: File creation failed\n");
    }
}
