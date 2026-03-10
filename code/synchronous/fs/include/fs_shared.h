#pragma once
#include <stdint.h>
#include <stddef.h>

#define CLIENT_BUFFER_SIZE 0x40000u

typedef struct {
    int rc;
    uint32_t file_id;
} fs_result_fileid_t;

typedef struct {
    int rc;
    uint8_t permissions;
} fs_result_permissions_t;

typedef struct {
    int rc;
    uint32_t size;
} fs_result_size_t;

typedef struct {
    int rc;
    uint8_t exists;
} fs_result_exists_t;

typedef struct {
    int rc;
    uint8_t *data_address;
    uint32_t bytes_read;
    uint32_t new_cursor_position;
} fs_result_read_t;

typedef struct {
    int rc;
    uint8_t *data_address;
} fs_result_list_t;

typedef struct {
    int rc;
    uint32_t bytes_written;
    uint32_t new_cursor_position;
} fs_result_write_t;