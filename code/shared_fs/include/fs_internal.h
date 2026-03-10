#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "fs_shared_types.h"

// System parameters
#ifndef NUMBER_OF_CLIENTS
#define NUMBER_OF_CLIENTS 1
#endif

#define BLOCK_SIZE 0x1000u

#define MAX_NUMBER_OF_BLOCKS 0x10000
#define MAX_NUMBER_OF_INODES 0x10000
#define DIRECT_BLOCKS_PER_INODE 11
#define MAX_OPEN_FILES_PER_CLIENT 256
#define MAX_OPERATIONS_PER_CLIENT_SERVICE (MAX_QUEUE_ENTRIES / 2)

#define FULL_PATH_EQUAL 0
#define FULL_PATH_NOT_EQUAL -1
#define PATH_SEGMENT_EQUAL 1

#define CREATE_DIRECTORY true
#define CREATE_FILE false
#define ROOT_DIRECTORY_I_NODE_INDEX 0u

// Maximums to check against
#define MAX_CHILD_ENTRIES_PER_BLOCK ((size_t)(BLOCK_SIZE / sizeof(child_entry_t)))
#define MAX_BLOCK_POINTERS_PER_INDIRECT_BLOCK ((size_t)(BLOCK_SIZE / sizeof(size_t)))
#define MAX_BLOCKS_PER_FILE (DIRECT_BLOCKS_PER_INODE + MAX_BLOCK_POINTERS_PER_INDIRECT_BLOCK)

// Function parameters
#define GET_PARENT_I_NODE true
#define GET_TARGET_I_NODE false
#define READ true
#define WRITE false
#define IS_FILE_BIT_SET 0b00
#define IS_DIRECTORY_BIT_SET 0b000010
#define IS_DELETED_BIT_SET 0b100000
#define IN_USE_BIT_SET 0b000001
#define PERMISSION_BITS_START 2
#define DIRECTORY_BIT_START 1

// ------------------------------ Structs ------------------------------- //

struct block {
    uint8_t data[BLOCK_SIZE];
} typedef block_t;

struct file_descriptor
{
    uint32_t i_node_index;
    size_t cursor_position;
    file_open_operations_t valid_operations;
    uint8_t padding[3];
} typedef file_descriptor_t;

struct i_node
{
    size_t entry_size;
    size_t blocks_used;
    size_t block_indices[DIRECT_BLOCKS_PER_INODE + 1]; // last is indirect block
    uint8_t mode; // 1 for deleted, 3 for perm, 1 for dir, 1 for in use 
    uint8_t owner_id;
    uint8_t padding[2];
} typedef i_node_t;

struct child_entry
{
    unsigned char name[MAX_NAME_LENGTH];
    uint32_t i_node_index;
} typedef child_entry_t;

struct fs_state
{
    uint8_t *block_table;
    file_descriptor_t *file_descriptor_table;
    i_node_t *i_node_table;
    block_t *blocks;
} typedef fs_state_t;

// ----------------- Result function return structs --------------------- //

struct file_descriptor_result
{
    file_descriptor_t *descriptor;
    uint8_t return_code;
} typedef file_descriptor_result_t;

struct file_id_and_cursor_result
{
    uint32_t file_id;
    size_t cursor_position;
    uint8_t return_code;
} typedef file_id_and_cursor_result_t;

struct i_node_result
{
    int32_t index;
    uint8_t return_code;
} typedef i_node_result_t;

struct block_id_result
{
    uint32_t index;
    uint8_t return_code;
} typedef block_id_result_t;

struct block_search_result
{
    size_t i_node_block_index;
    size_t block_offset;
    bool is_indirect;
} typedef block_search_result_t;

struct child_slot_and_block_result {
    size_t block_index;
    size_t entry_index;
    uint8_t return_code;
} typedef child_slot_and_block_result_t;
