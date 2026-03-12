#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "debug_output.h"

#include "fs_internal.h"


int32_t compare_names(const unsigned char *name1, const unsigned char *name2) {
    for (size_t i = 0; i < MAX_NAME_LENGTH; i++) {
        if (name1[i] == '/') {
            return PATH_SEGMENT_EQUAL;
        }
        if (name1[i] == '\0') {
            return FULL_PATH_EQUAL;
        }
        if (name1[i] != name2[i]) {
            return FULL_PATH_NOT_EQUAL;
        }
    }
    return 0; 
}


bool valid_name(const unsigned char *name) {
    if (name[0] == '\0' || name[0] == '/') {
        return 0;
    }
    for (size_t i = 0; i < MAX_NAME_LENGTH; i++) {
        if (name[i] == '\0') {
            return 1;
        }
        if (name[i] == '/') {
            return 0;
        }
    }

    // name must end with \0
    return 0;
}


bool valid_permissions(const i_node_t *i_node, const uint8_t client_id, const permissions_t required) {
    // can perform any op on own file
    if (i_node->owner_id == client_id) {
        return 1;
    }

    permissions_t perm = (i_node->mode >> PERMISSION_BITS_START) & 0b111;
    if ((perm & required) == required) {
        return 1;
    }

    return 0;
}


void copy_data_from_buffer(const uint8_t *src, uint8_t *dest, const size_t length) {
    for (size_t i = 0; i < length; i++) {
        dest[i] = src[i];
    }
}


size_t copy_string_from_buffer(const unsigned char *src, unsigned char *dest, const size_t max_length) {
    size_t i;
    for (i = 0; i < max_length - 1; i++) {
        dest[i] = src[i];
        if (dest[i] == '\0') {
            return i;
        }
    }
    // truncate if it exceeds max_length
    dest[max_length - 1] = '\0';
    return max_length - 1;
}


void zero_block(unsigned char *block) {
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        block[i] = 0;
    }
}