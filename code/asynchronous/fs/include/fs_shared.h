#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "fs_shared_types.h"

#define CLIENT_BENCHMARK_LABEL 1
#define CLIENT_BUFFER_SIZE 0x1000u
#define CLIENT_DATA_PAGE_SIZE 0x81000u

#define NUMBER_OF_BUFFERS_PER_CLIENT 64

struct client_flags {
    bool ready_flag;
    bool complete_flag;
    bool finished_running_flag;
    uint8_t padding;
} typedef client_flags_t;

struct buffer {
    uint8_t data[CLIENT_BUFFER_SIZE];
} typedef buffer_t;

struct submission_queue_entry
{
    operation_t operation_code;
    uint32_t parameter1;
    uint32_t parameter2;
    size_t buffer_index;
} typedef submission_queue_entry_t;

struct completion_queue_entry
{
    uint8_t return_code;
    uint32_t parameter1;
    uint32_t parameter2;
    size_t buffer_index;
} typedef completion_queue_entry_t;

#define CLIENT_DATA_INTERNAL_ALIGNMENT_PADDING ((sizeof(size_t) - (sizeof(client_flags_t) % sizeof(size_t))) % sizeof(size_t))
#define CLIENT_DATA_PADDING_AMOUNT (CLIENT_DATA_PAGE_SIZE - (sizeof(client_flags_t) + sizeof(size_t) * 4 + sizeof(submission_queue_entry_t) * MAX_QUEUE_ENTRIES + sizeof(completion_queue_entry_t) * MAX_QUEUE_ENTRIES + sizeof(uint8_t) * NUMBER_OF_BUFFERS_PER_CLIENT * 2 + sizeof(buffer_t) * NUMBER_OF_BUFFERS_PER_CLIENT * 2 + CLIENT_DATA_INTERNAL_ALIGNMENT_PADDING))

struct client {
    size_t submission_queue_head;
    size_t submission_queue_tail;
    size_t completion_queue_head;
    size_t completion_queue_tail;
    client_flags_t flags;
    submission_queue_entry_t submission_queue[MAX_QUEUE_ENTRIES];
    completion_queue_entry_t completion_queue[MAX_QUEUE_ENTRIES];
    bool submission_buffer_table[NUMBER_OF_BUFFERS_PER_CLIENT];
    bool completion_buffer_table[NUMBER_OF_BUFFERS_PER_CLIENT];
    buffer_t submission_buffers[NUMBER_OF_BUFFERS_PER_CLIENT];
    buffer_t completion_buffers[NUMBER_OF_BUFFERS_PER_CLIENT];
    uint8_t padding[CLIENT_DATA_PADDING_AMOUNT];
} typedef client_t;

_Static_assert(sizeof(client_t) == CLIENT_DATA_PAGE_SIZE, "client_t must exactly match CLIENT_DATA_PAGE_SIZE");
