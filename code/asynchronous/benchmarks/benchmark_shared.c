#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "benchmark_shared.h"

static size_t append_c_string(unsigned char *dest, size_t offset, size_t capacity,
                              const char *src)
{
    size_t index = offset;

    while (*src != '\0' && index + 1 < capacity) {
        dest[index++] = (unsigned char)*src++;
    }

    if (index < capacity) {
        dest[index] = '\0';
    }

    return index;
}

static size_t append_u32(unsigned char *dest, size_t offset, size_t capacity,
                         uint32_t value)
{
    char digits[10];
    size_t count = 0;
    size_t index = offset;

    if (value == 0) {
        if (index + 1 < capacity) {
            dest[index++] = '0';
            dest[index] = '\0';
        }
        return index;
    }

    while (value > 0 && count < sizeof(digits)) {
        digits[count++] = (char)('0' + (value % 10u));
        value /= 10u;
    }

    while (count > 0 && index + 1 < capacity) {
        dest[index++] = (unsigned char)digits[--count];
    }

    if (index < capacity) {
        dest[index] = '\0';
    }

    return index;
}

void benchmark_make_file_path(unsigned char *dest, size_t capacity,
                              const unsigned char *root_path, uint32_t iteration)
{
    size_t index = 0;
    const unsigned char *src = root_path;

    while (*src != '\0' && index + 1 < capacity) {
        dest[index++] = *src++;
    }

    if (index + 1 < capacity) {
        dest[index++] = '/';
        dest[index] = '\0';
    }

    index = append_c_string(dest, index, capacity, "file_");
    index = append_u32(dest, index, capacity, iteration);
    append_c_string(dest, index, capacity, ".bin");
}

void benchmark_copy_path(unsigned char *dest, size_t capacity,
                         const unsigned char *src)
{
    size_t index = 0;

    while (*src != '\0' && index + 1 < capacity) {
        dest[index++] = *src++;
    }

    if (index < capacity) {
        dest[index] = '\0';
    }
}

void benchmark_fill_pattern(uint8_t *buffer, size_t length, uint32_t seed)
{
    for (size_t i = 0; i < length; i++) {
        buffer[i] = (uint8_t)((seed + i) & 0xffu);
    }
}

bool benchmark_buffers_equal(const uint8_t *lhs, const uint8_t *rhs, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        if (lhs[i] != rhs[i]) {
            return false;
        }
    }

    return true;
}

void benchmark_clear_client_state(client_t *client_data)
{
    client_data->submission_queue_head = 0;
    client_data->submission_queue_tail = 0;
    client_data->completion_queue_head = 0;
    client_data->completion_queue_tail = 0;
    client_data->flags.ready_flag = 0;
    client_data->flags.complete_flag = 0;
    client_data->flags.finished_running_flag = 0;

    for (size_t i = 0; i < MAX_QUEUE_ENTRIES; i++) {
        client_data->submission_queue[i].operation_code = 0;
        client_data->submission_queue[i].parameter1 = 0;
        client_data->submission_queue[i].parameter2 = 0;
        client_data->submission_queue[i].buffer_index = 0;
        client_data->completion_queue[i].return_code = 0;
        client_data->completion_queue[i].parameter1 = 0;
        client_data->completion_queue[i].parameter2 = 0;
        client_data->completion_queue[i].buffer_index = 0;
    }

    for (size_t i = 0; i < NUMBER_OF_BUFFERS_PER_CLIENT; i++) {
        client_data->submission_buffer_table[i] = false;
        client_data->completion_buffer_table[i] = false;
        for (size_t j = 0; j < CLIENT_BUFFER_SIZE; j++) {
            client_data->submission_buffers[i].data[j] = 0;
            client_data->completion_buffers[i].data[j] = 0;
        }
    }
}