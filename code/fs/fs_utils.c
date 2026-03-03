#include <stdint.h>
#include <stddef.h>
#include "fs_internal.h"
#include "fs_shared.h"


int operation_requires_completion_buffer(file_operation_t operation) {
    if (operation == OP_READ || operation == OP_LIST || operation == OP_GET_PERMISSIONS ||
        operation == OP_GET_SIZE || operation == OP_EXISTS
    ) {
        return 1;
    }

    return 0;
}

int operation_requires_submission_buffer(file_operation_t operation) {
    if (operation == OP_CREATE_FILE || operation == OP_CREATE_DIRECTORY || operation == OP_OPEN ||
        operation == OP_DELETE || operation == OP_SET_PERMISSIONS || operation == OP_GET_PERMISSIONS ||
        operation == OP_GET_SIZE || operation == OP_EXISTS || operation == OP_LIST
    ) {
        return 1;
    }

    return 0;
}


int32_t compare_names(const unsigned char *name1, const unsigned char *name2) {
    for (size_t i = 0; i < MAX_NAME_LENGTH; i++) {
        if (name1[i] == '/') {
            microkit_dbg_puts("part\n");
            return PATH_SEGMENT_EQUAL;
        }
        if (name1[i] == '\0') {
            microkit_dbg_puts("full\n");
            return FULL_PATH_EQUAL;
        }
        if (name1[i] != name2[i]) {
            microkit_dbg_puts("not\n");
            return FULL_PATH_NOT_EQUAL;
        }
    }
    microkit_dbg_puts("eq2\n");
    return 0; 
}


int valid_name(const unsigned char *name) {
    microkit_dbg_puts("validating name: ");
    microkit_dbg_puts((const char *)name);
    microkit_dbg_puts("\n");
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
    return 0;
}


int valid_permissions(const i_node_t *i_node, const uint8_t client_id, const permissions_t required) {
    if (i_node->owner_id == client_id) {
        return 1;
    }
    permissions_t dir_perm = (i_node->mode >> 2) & 0b111;
    microkit_dbg_puts("checking permissions: ");
    microkit_dbg_put32(dir_perm);
    microkit_dbg_puts(" against required: ");
    microkit_dbg_put32(required);
    microkit_dbg_puts("\n");
    if ((dir_perm & required) == required) {
        return 1;
    }
    return 0;
}


void copy_data_from_buffer(const uint8_t *src, uint8_t *dest, size_t length) {
    for (size_t i = 0; i < length; i++) {
        dest[i] = src[i];
    }
}


size_t copy_string_from_buffer(const unsigned char *src, unsigned char *dest, size_t max_length) {
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