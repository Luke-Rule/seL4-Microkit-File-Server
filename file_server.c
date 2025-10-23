// ----------------------------------------------------------------------- //
// ------------------------ MicroKit File Server ------------------------- //
// ----------------------------------------------------------------------- //


// ------------------------------ Includes ------------------------------- //

#include <microkit.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


// ------------------------------ Definitions ----------------------------- //

// System parameters
#define NUMBER_OF_CLIENTS 2

// Client memory
#define CLIENT_BUFFER_SIZE 0x1000
#define CLIENT_BUFFER_BASE(client_id) ((uintptr_t)lowest_client_buffer_base + (uintptr_t)(client_id * CLIENT_BUFFER_SIZE))

// File server memory
#define FILE_TABLE_SIZE 0x10000
#define FILE_DATA_SIZE 0x100000
#define MAX_FILE_NAME_LENGTH 64 // TODO: update functions to handle null terminator reducing this by 1
#define MAX_FILE_SIZE 0x100000
#define FILE_ENTRY_SIZE sizeof(struct file_entry)
#define MAX_FILE_TABLE_ENTRIES (FILE_TABLE_SIZE / FILE_ENTRY_SIZE)
#define FILE_ENTRY_OFFSET(index) (file_table_base + (index * FILE_ENTRY_SIZE))
#define FILE_DATA_OFFSET(offset) (file_data_base + offset)

// File operations 
typedef enum {
    OP_CREATE = 0,
    OP_READ = 1,
    OP_WRITE = 2,
    OP_OPEN = 3, // not used yet
    OP_CLOSE = 4, // not used yet
    OP_DELETE = 5,
    OP_LIST = 6,
    OP_SET_PERMISSIONS = 7,
    OP_GET_PERMISSIONS = 8,
    OP_RENAME = 9,
    OP_GET_FILE_SIZE = 10,
    OP_EXISTS = 11,
    OP_COPY = 12
} file_operation_t;

// File operation permissions (higher value includes lower levels)
typedef enum {
    FILE_PERM_PRIVATE = 0,
    FILE_PERM_PUBLIC_EXISTS_AND_LIST = 1,
    FILE_PERM_PUBLIC_GET_FILE_SIZE = 2,
    FILE_PERM_PUBLIC_GET_PERMISSIONS = 3,
    FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE = 4,
    FILE_PERM_PUBLIC_WRITE_AND_DELETE_AND_RENAME = 5,
    FILE_PERM_PUBLIC_SET_PERMISSIONS = 6
} file_permission_t;

// Result codes (0 == success, other gives failure reason)
typedef enum {
    FS_OK = 0,
    FS_ERR_TABLE_FULL = 1,
    FS_ERR_FILE_EXCEEDS_MAX_SIZE = 2,
    FS_ERR_FILE_EXCEEDS_REMAINING_SPACE = 3,
    FS_ERR_INVALID_NAME = 4,
    FS_ERR_ALREADY_EXISTS = 5,
    FS_ERR_NOT_FOUND = 6,
    FS_ERR_PERMISSION = 7,
    FS_ERR_OUT_OF_BOUNDS = 8,
    FS_ERR_NAME_COLLISION = 9,
    FS_ERR_INVALID_OP_CODE = 10,
    FS_ERR_INCORRECT_OP_PARAM_COUNT = 11,
    FS_ERR_UNSPECIFIED_ERROR = 12
} fs_result_t;


// ------------------------------ Globals ------------------------------- //

struct file_entry
{
    unsigned char name[MAX_FILE_NAME_LENGTH];
    uint8_t owner_id;
    uint32_t data_offset;
    uint32_t size;
    uint8_t permissions; 
} typedef file_entry_t;

file_entry_t *file_table_base;
size_t file_table_index = 0;
uint8_t *file_data_base;
size_t file_data_index = 0;
uint8_t *lowest_client_buffer_base;


// --------------------------- Helper Functions -------------------------- //

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

bool string_compare(const unsigned char *str1, const unsigned char *str2, size_t max_length) {
    for (size_t i = 0; i < max_length; i++) {
        if (str1[i] != str2[i]) {
            return false;
        }
        if (str1[i] == '\0') {
            break;
        }
    }
    return true;
}

bool file_exists(const unsigned char *name) {
    for (size_t i = 0; i < file_table_index; i++) {
        file_entry_t* entry = &file_table_base[i];
        if (entry->name[0] != '\0' && string_compare(name, entry->name, MAX_FILE_NAME_LENGTH)) {
            return true;
        }
    }
    return false;
}

file_entry_t* get_file_entry(const unsigned char *name) {
    for (size_t i = 0; i < file_table_index; i++) {
        file_entry_t* entry = &file_table_base[i];
        if (entry->name[0] != '\0' && string_compare(name, entry->name, MAX_FILE_NAME_LENGTH)) {
            return entry;
        }
    }
    return NULL;
}


static int check_permission(file_entry_t *entry, uint32_t client_id, file_permission_t required) {
    if (entry->owner_id == client_id) return FS_OK;
    if ((file_permission_t)entry->permissions >= required) return FS_OK;
    return FS_ERR_PERMISSION;
}


// -------------------------- File Operations --------------------------- //

int create_file_operation(const uint32_t client_id, const uint32_t size, const uint8_t permissions) {
    if (file_table_index >= MAX_FILE_TABLE_ENTRIES) {
        return FS_ERR_TABLE_FULL;
    }
    if (size > MAX_FILE_SIZE) {
        return FS_ERR_FILE_EXCEEDS_MAX_SIZE;
    }
    if ((file_data_index + size) > FILE_DATA_SIZE) {
        return FS_ERR_FILE_EXCEEDS_REMAINING_SPACE;
    }

    unsigned char *name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);

    if (string_compare(name, (unsigned char *)"\0", MAX_FILE_NAME_LENGTH)) {
        return FS_ERR_INVALID_NAME;
    }

    if (file_exists(name)) {
        return FS_ERR_ALREADY_EXISTS;
    }

    size_t empty_index = file_table_index + 1;

    for (size_t i = 0; i < file_table_index; i++) {
        file_entry_t* entry = &file_table_base[i];
        if (entry->name[0] == '\0') {
            empty_index = i;
            break;
        }
    }

    if (empty_index == file_table_index + 1) {
        file_table_index++;
    }

    file_entry_t* entry = &file_table_base[empty_index];
    copy_string_from_buffer(name, entry->name, MAX_FILE_NAME_LENGTH);
    entry->owner_id = client_id;
    // TODO: check for deleted files and reuse their data segments
    entry->data_offset = file_data_index;
    entry->size = size;
    entry->permissions = permissions;

    file_data_index += size;

    return FS_OK;
}


int read_file_operation(const uint32_t client_id, const uint32_t offset, const size_t length) {
    unsigned char *client_buffer = (unsigned char *)CLIENT_BUFFER_BASE(client_id);
    file_entry_t* entry = get_file_entry(client_buffer);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE);
    if (perm != FS_OK) return perm;

    if (offset >= entry->size || offset + length >= entry->size) {
        return FS_ERR_OUT_OF_BOUNDS;
    }

    uint8_t *file_data_ptr = FILE_DATA_OFFSET(entry->data_offset + offset);
    copy_data_from_buffer(file_data_ptr, (uint8_t *)client_buffer, length);

    return FS_OK;
}


int write_file_operation(const uint32_t client_id, const uint32_t data_start_index, const uint32_t offset, const size_t length) {
    unsigned char *name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);

    file_entry_t* entry = get_file_entry(name);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_WRITE_AND_DELETE_AND_RENAME);
    if (perm != FS_OK) return perm;

    if (offset >= entry->size || offset + length >= entry->size) {
        return FS_ERR_OUT_OF_BOUNDS;
    }
    if (data_start_index >= CLIENT_BUFFER_SIZE || data_start_index + length >= CLIENT_BUFFER_SIZE) {
        return FS_ERR_OUT_OF_BOUNDS;
    }
    uint8_t *client_data = (uint8_t *)CLIENT_BUFFER_BASE(client_id) + data_start_index;
    uint8_t *file_data_ptr = FILE_DATA_OFFSET(entry->data_offset + offset);
    copy_data_from_buffer(client_data, file_data_ptr, length);

    return FS_OK;
}


int delete_file_operation(const uint32_t client_id) {
    unsigned char *name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);

    file_entry_t* entry = get_file_entry(name);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_WRITE_AND_DELETE_AND_RENAME);
    if (perm != FS_OK) return perm;

    entry->name[0] = '\0';
    // TODO: handle file data cleanup

    return FS_OK;
}


int list_files_operation(const uint32_t client_id) {
    unsigned char *client_buffer = (unsigned char *)CLIENT_BUFFER_BASE(client_id);
    size_t buffer_index = 0;

    for (size_t i = 0; i < file_table_index; i++) {
        file_entry_t* entry = &file_table_base[i];
        if (entry->name[0] != '\0') {
            if ((entry->permissions > FILE_PERM_PRIVATE) || entry->owner_id == client_id) {
                if (buffer_index + MAX_FILE_NAME_LENGTH + 1 >= CLIENT_BUFFER_SIZE) {
                    break;
                }
                size_t name_length = copy_string_from_buffer(entry->name, &client_buffer[buffer_index], MAX_FILE_NAME_LENGTH);
                buffer_index += name_length + 1; // + 1 for terminator char
                client_buffer[buffer_index] = '\n';
                buffer_index++;
            }
        }
    }

    if (buffer_index > 0) {
        client_buffer[buffer_index - 1] = '\0';
    } else {
        client_buffer[0] = '\0';
    }

    return FS_OK;
}


int set_file_permissions_operation(const uint32_t client_id, const uint8_t permissions) {
    unsigned char *name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);

    file_entry_t* entry = get_file_entry(name);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_SET_PERMISSIONS);
    if (perm != FS_OK) return perm;

    entry->permissions = permissions;

    return FS_OK;
}


int get_file_permissions_operation(const uint32_t client_id) {
    unsigned char *name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);

    file_entry_t* entry = get_file_entry(name);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_GET_PERMISSIONS);
    if (perm != FS_OK) return perm;

    uint8_t *client_buffer = (uint8_t *)CLIENT_BUFFER_BASE(client_id);
    client_buffer[0] = entry->permissions;
    return FS_OK;
}


int rename_file_operation(const uint32_t client_id, const uint32_t new_name_index) {
    unsigned char *old_name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);
    unsigned char *new_name = (unsigned char *)CLIENT_BUFFER_BASE(client_id) + new_name_index;

    file_entry_t* entry = get_file_entry(old_name);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_WRITE_AND_DELETE_AND_RENAME);
    if (perm != FS_OK) return perm;

    copy_string_from_buffer(new_name, entry->name, MAX_FILE_NAME_LENGTH);

    return FS_OK;
}


int get_file_size_operation(const uint32_t client_id) {
    unsigned char *name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);

    file_entry_t* entry = get_file_entry(name);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_GET_FILE_SIZE);
    if (perm != FS_OK) return perm;

    uint32_t *client_buffer = (uint32_t *)CLIENT_BUFFER_BASE(client_id);
    client_buffer[0] = entry->size;
    return FS_OK;
}


int file_exists_operation(const uint32_t client_id) {
    unsigned char *name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);
    file_entry_t* entry = get_file_entry(name);
    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_EXISTS_AND_LIST);
    if (perm != FS_OK) return perm;
    return FS_OK;
}


int copy_file_operation(const uint32_t client_id, const uint32_t new_file_name_index) {
    unsigned char *old_file = (unsigned char *)CLIENT_BUFFER_BASE(client_id);
    unsigned char *dest_name = (unsigned char *)CLIENT_BUFFER_BASE(client_id) + new_file_name_index;

    if (string_compare(old_file, dest_name, MAX_FILE_NAME_LENGTH)) {
        return FS_ERR_NAME_COLLISION;
    }

    if (file_exists(dest_name)) {
        return FS_ERR_ALREADY_EXISTS;
    }

    file_entry_t* source_entry = get_file_entry(old_file);

    if (source_entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(source_entry, client_id, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE);
    if (perm != FS_OK) return perm;


    int return_code = create_file_operation(client_id, source_entry->size, source_entry->permissions);
    if (return_code != FS_OK) {
        return return_code;
    }

    file_entry_t* dest_entry = get_file_entry(dest_name);

    // TODO: only copy data if its later modified
    uint8_t *source_data_ptr = FILE_DATA_OFFSET(source_entry->data_offset);
    uint8_t *dest_data_ptr = FILE_DATA_OFFSET(dest_entry->data_offset);
    copy_data_from_buffer(source_data_ptr, dest_data_ptr, source_entry->size);

    return FS_OK;
}


// ------------------------- MicroKit Interface -------------------------- //

void init(void) {}

void notified(microkit_channel client_id) {}

microkit_msginfo protected(microkit_channel channel, microkit_msginfo msginfo) {
    if (microkit_msginfo_get_count(msginfo) < 1) {
        microkit_mr_set(0, FS_ERR_INVALID_OP_CODE);
        return msginfo;
    }

    uint32_t operation = microkit_mr_get(0);
    int return_code = FS_ERR_UNSPECIFIED_ERROR;

    switch (operation) {
        case OP_CREATE: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t size = microkit_mr_get(1);
            uint8_t permissions = (uint8_t)microkit_mr_get(2);
            return_code = create_file_operation(channel, size, permissions);
            break;
        }

        case OP_READ: {
            if (microkit_msginfo_get_count(msginfo) < 3) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t offset = microkit_mr_get(1);
            size_t length = (size_t)microkit_mr_get(2);
            return_code = read_file_operation(channel, offset, length);
            break;
        }

        case OP_WRITE: {
            if (microkit_msginfo_get_count(msginfo) < 4) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t data_start_index = microkit_mr_get(1);
            uint32_t write_offset = microkit_mr_get(2);
            size_t write_length = (size_t)microkit_mr_get(3);
            return_code = write_file_operation(channel, data_start_index, write_offset, write_length);
            break;
        }

        case OP_OPEN:
            /* code */
            break;

        case OP_CLOSE:
            /* code */
            break;

        case OP_DELETE: {
            return_code = delete_file_operation(channel);
            break;
        }

        case OP_LIST: {
            return_code = list_files_operation(channel);
            break;
        }
            
        case OP_SET_PERMISSIONS: {
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint8_t new_permissions = (uint8_t)microkit_mr_get(1);
            return_code = set_file_permissions_operation(channel, new_permissions);
            break;
        }

        case OP_GET_PERMISSIONS: {
            return_code = get_file_permissions_operation(channel);
            break;
        }

        case OP_RENAME: {
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t new_name_index = microkit_mr_get(1);
            return_code = rename_file_operation(channel, new_name_index);
            break;
        }

        case OP_GET_FILE_SIZE: {
            return_code = get_file_size_operation(channel);
            break;
        }

        case OP_EXISTS: {
            return_code = file_exists_operation(channel);
            break;
        }

        case OP_COPY: {
            if (microkit_msginfo_get_count(msginfo) < 2) {
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t new_file_name_index = microkit_mr_get(1);
            return_code = copy_file_operation(channel, new_file_name_index);
            break;
        }

        default:
            return_code = FS_ERR_INVALID_OP_CODE;
            break;
    }

    microkit_mr_set(0, return_code);

    return msginfo;
}