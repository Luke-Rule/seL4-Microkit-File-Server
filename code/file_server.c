// ----------------------------------------------------------------------- //
// ------------------------ MicroKit File Server ------------------------- //
// ----------------------------------------------------------------------- //


// ------------------------------ Includes ------------------------------- //

#include <microkit.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "definitions.h"

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

// ------------------------------ Globals ------------------------------- //

struct file_entry
{
    uint32_t id;
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

file_entry_t* get_file_entry_by_id(uint32_t id) {
    for (size_t i = 0; i < file_table_index; i++) {
        if (file_table_base[i].id == id && file_table_base[i].name[0] != '\0') {
            return &file_table_base[i];
        }
    }
    return NULL;
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
    entry->id = file_table_index;
    copy_string_from_buffer(name, entry->name, MAX_FILE_NAME_LENGTH);
    entry->owner_id = client_id;
    // TODO: check for deleted files and reuse their data segments
    entry->data_offset = file_data_index;
    entry->size = size;
    entry->permissions = permissions;

    file_data_index += size;

    // write file id back to client
    uint32_t *client_buffer = (uint32_t *)CLIENT_BUFFER_BASE(client_id);
    client_buffer[0] = (entry->id >> 0)  & 0xFF;
    client_buffer[1] = (entry->id >> 8)  & 0xFF;
    client_buffer[2] = (entry->id >> 16) & 0xFF;
    client_buffer[3] = (entry->id >> 24) & 0xFF;

    microkit_dbg_puts("FILE SERVER: Created file '");
    microkit_dbg_puts((const char *)entry->name);
    microkit_dbg_puts("'\n");

    return entry->id;
}


int open_file_operation(const uint32_t client_id) {
    unsigned char *name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);
    file_entry_t* entry = get_file_entry(name);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE);
    if (perm != FS_OK) return perm;

    uint32_t *client_buffer = (uint32_t *)CLIENT_BUFFER_BASE(client_id);
    client_buffer[0] = (entry->id >> 0)  & 0xFF;
    client_buffer[1] = (entry->id >> 8)  & 0xFF;
    client_buffer[2] = (entry->id >> 16) & 0xFF;
    client_buffer[3] = (entry->id >> 24) & 0xFF;

    microkit_dbg_puts("FILE SERVER: Opened file '");
    microkit_dbg_puts((const char *)entry->name);
    microkit_dbg_puts("'\n");

    return FS_OK;
}


int read_file_operation(const uint32_t client_id, const uint32_t file_id, const uint32_t offset, const size_t length) {
    unsigned char *client_buffer = (unsigned char *)CLIENT_BUFFER_BASE(client_id);
    file_entry_t* entry = get_file_entry_by_id(file_id);

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

    microkit_dbg_puts("FILE SERVER: Read file '");
    microkit_dbg_puts((const char *)entry->name);
    microkit_dbg_puts("'\n");
    microkit_dbg_puts("FILE SERVER: Data: ");
    for (size_t i = 0; i < length; i++) {
        microkit_dbg_putc((char)client_buffer[i]);
    }
    microkit_dbg_puts("\n");

    return FS_OK;
}


int write_file_operation(const uint32_t client_id, const uint32_t file_id, const uint32_t offset, const size_t length) {
    file_entry_t* entry = get_file_entry_by_id(file_id);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_WRITE_AND_DELETE_AND_RENAME);
    if (perm != FS_OK) return perm;

    if (offset >= entry->size || offset + length >= entry->size) {
        return FS_ERR_OUT_OF_BOUNDS;
    }

    uint8_t *client_data = (uint8_t *)CLIENT_BUFFER_BASE(client_id);
    uint8_t *file_data_ptr = FILE_DATA_OFFSET(entry->data_offset + offset);
    copy_data_from_buffer(client_data, file_data_ptr, length);

    microkit_dbg_puts("FILE SERVER: Wrote to file '");
    microkit_dbg_puts((const char *)entry->name);
    microkit_dbg_puts("'\n");
    microkit_dbg_puts("FILE SERVER: Data: ");
    for (size_t i = 0; i < length; i++) {
        microkit_dbg_putc((char)client_data[i]);
    }
    microkit_dbg_puts("\n");

    return FS_OK;
}


int delete_file_operation(const uint32_t client_id, const uint32_t file_id) {
    file_entry_t* entry = get_file_entry_by_id(file_id);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_WRITE_AND_DELETE_AND_RENAME);
    if (perm != FS_OK) return perm;

    entry->name[0] = '\0';
    // TODO: handle file data cleanup

    microkit_dbg_puts("FILE SERVER: Deleted file '");
    microkit_dbg_puts((const char *)entry->name);
    microkit_dbg_puts("'\n");

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

    microkit_dbg_puts("FILE SERVER: Listed files:\n");
    microkit_dbg_puts((const char *)client_buffer);
    microkit_dbg_puts("\n");

    return FS_OK;
}


int set_file_permissions_operation(const uint32_t client_id, const uint32_t file_id, const uint8_t permissions) {
    file_entry_t* entry = get_file_entry_by_id(file_id);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_SET_PERMISSIONS);
    if (perm != FS_OK) return perm;

    entry->permissions = permissions;

    microkit_dbg_puts("FILE SERVER: Set permissions for file '");
    microkit_dbg_puts((const char *)entry->name);
    microkit_dbg_puts("'\n");
    microkit_dbg_puts("FILE SERVER: New permissions: ");
    microkit_dbg_put8(permissions);
    microkit_dbg_puts("\n");

    return FS_OK;
}


int get_file_permissions_operation(const uint32_t client_id, const uint32_t file_id) {
    file_entry_t* entry = get_file_entry_by_id(file_id);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_GET_PERMISSIONS);
    if (perm != FS_OK) return perm;

    uint8_t *client_buffer = (uint8_t *)CLIENT_BUFFER_BASE(client_id);
    client_buffer[0] = entry->permissions;

    microkit_dbg_puts("FILE SERVER: Got permissions for file '");
    microkit_dbg_puts((const char *)entry->name);
    microkit_dbg_puts("'\n");
    microkit_dbg_puts("FILE SERVER: Permissions: ");
    microkit_dbg_put8(entry->permissions);
    microkit_dbg_puts("\n");

    return FS_OK;
}


int rename_file_operation(const uint32_t client_id, const uint32_t file_id) {
    unsigned char *new_name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);
    file_entry_t* entry = get_file_entry_by_id(file_id);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_WRITE_AND_DELETE_AND_RENAME);
    if (perm != FS_OK) return perm;

    copy_string_from_buffer(new_name, entry->name, MAX_FILE_NAME_LENGTH);

    microkit_dbg_puts("FILE SERVER: Renamed file '");
    microkit_dbg_puts((const char *)entry->name);
    microkit_dbg_puts("'\n");
    microkit_dbg_puts("FILE SERVER: New name: ");
    microkit_dbg_puts((const char *)new_name);
    microkit_dbg_puts("\n");

    return FS_OK;
}


int get_file_size_operation(const uint32_t client_id, const uint32_t file_id) {
    file_entry_t* entry = get_file_entry_by_id(file_id);

    if (entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    int perm = check_permission(entry, client_id, FILE_PERM_PUBLIC_GET_FILE_SIZE);
    if (perm != FS_OK) return perm;

    uint32_t *client_buffer = (uint32_t *)CLIENT_BUFFER_BASE(client_id);
    client_buffer[0] = entry->size;

    microkit_dbg_puts("FILE SERVER: Got size for file '");
    microkit_dbg_puts((const char *)entry->name);
    microkit_dbg_puts("'\n");
    microkit_dbg_puts("FILE SERVER: Size: ");
    microkit_dbg_put32(entry->size);
    microkit_dbg_puts("\n");

    return FS_OK;
}


int file_exists_operation(const uint32_t client_id) {
    unsigned char *name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);
    file_entry_t* entry = get_file_entry(name);
    if (entry != NULL && (entry->permissions > FILE_PERM_PRIVATE || entry->owner_id == client_id)) {
        uint8_t *client_buffer = (uint8_t *)CLIENT_BUFFER_BASE(client_id);
        client_buffer[0] = 1; // true
    } else {
        uint8_t *client_buffer = (uint8_t *)CLIENT_BUFFER_BASE(client_id);
        client_buffer[0] = 0; // false
    }
    microkit_dbg_puts("FILE SERVER: Checked existence for file '");
    microkit_dbg_puts((const char *)name);
    microkit_dbg_puts("'\n");
    microkit_dbg_puts("FILE SERVER: Exists: ");
    if (entry != NULL) {
        microkit_dbg_puts("true\n");
    } else {
        microkit_dbg_puts("false\n");
    }
    return FS_OK;
}


int copy_file_operation(const uint32_t client_id, const uint32_t source_file_id) {
    unsigned char *dest_name = (unsigned char *)CLIENT_BUFFER_BASE(client_id);

    file_entry_t* source_entry = get_file_entry_by_id(source_file_id);

    if (source_entry == NULL) {
        return FS_ERR_NOT_FOUND;
    }

    if (string_compare(source_entry->name, dest_name, MAX_FILE_NAME_LENGTH)) {
        return FS_ERR_NAME_COLLISION;
    }

    if (file_exists(dest_name)) {
        return FS_ERR_ALREADY_EXISTS;
    }

    int perm = check_permission(source_entry, client_id, FILE_PERM_PUBLIC_READ_AND_COPY_AND_OPEN_AND_CLOSE);
    if (perm != FS_OK) return perm;

    // this will write the new file id back to the client buffer
    uint32_t file_id = create_file_operation(client_id, source_entry->size, source_entry->permissions);
    // if negative, there was an error, otherwise file id is returned
    if (file_id < FS_OK) {
        return file_id;
    }

    file_entry_t* dest_entry = get_file_entry_by_id((uint32_t)file_id);
    if (dest_entry == NULL) {
        return FS_ERR_UNSPECIFIED_ERROR;
    }

    // TODO: only copy data if its later modified
    uint8_t *source_data_ptr = FILE_DATA_OFFSET(source_entry->data_offset);
    uint8_t *dest_data_ptr = FILE_DATA_OFFSET(dest_entry->data_offset);
    copy_data_from_buffer(source_data_ptr, dest_data_ptr, source_entry->size);

    microkit_dbg_puts("FILE SERVER: Copied file '");
    microkit_dbg_puts((const char *)source_entry->name);
    microkit_dbg_puts("' to '");
    microkit_dbg_puts((const char *)dest_entry->name);
    microkit_dbg_puts("'\n");
    microkit_dbg_puts("FILE SERVER: New file ID: ");
    microkit_dbg_put32(dest_entry->id);
    microkit_dbg_puts("\n");
    microkit_dbg_puts("FILE SERVER: Data: ");
    for (size_t i = 0; i < dest_entry->size; i++) {
        microkit_dbg_putc((char)dest_data_ptr[i]);
    }

    return FS_OK;
}


// ------------------------- MicroKit Interface -------------------------- //

void init(void) {
    microkit_dbg_puts("FILE SERVER: started\n");
}

void notified(microkit_channel client_id) {}

microkit_msginfo protected(microkit_channel channel, microkit_msginfo msginfo) {
    microkit_dbg_puts("FILE SERVER: received request\n");
    if (microkit_msginfo_get_count(msginfo) < 1) {
        microkit_dbg_puts("FILE SERVER: invalid operation code\n");
        microkit_mr_set(0, FS_ERR_INVALID_OP_CODE);
        return msginfo;
    }

    uint32_t operation = microkit_mr_get(0);
    int return_code = FS_ERR_UNSPECIFIED_ERROR;

    switch (operation) {
        case OP_CREATE: {
            microkit_dbg_puts("FILE SERVER: processing create operation\n");
            if (microkit_msginfo_get_count(msginfo) < 3) {
                microkit_dbg_puts("FILE SERVER: incorrect operation parameter count\n");
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t size = microkit_mr_get(1);
            uint8_t permissions = (uint8_t)microkit_mr_get(2);
            return_code = create_file_operation(channel, size, permissions);
            // if no error, translate file id to FS_OK
            if (return_code >= FS_OK) {
                return_code = FS_OK;
            }
            break;
        }

        case OP_READ: {
            microkit_dbg_puts("FILE SERVER: processing read operation\n");
            if (microkit_msginfo_get_count(msginfo) < 3) {
                microkit_dbg_puts("FILE SERVER: incorrect operation parameter count\n");
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            uint32_t offset = microkit_mr_get(2);
            size_t length = (size_t)microkit_mr_get(3);
            return_code = read_file_operation(channel, file_id, offset, length);
            break;
        }

        case OP_WRITE: {
            microkit_dbg_puts("FILE SERVER: processing write operation\n");
            if (microkit_msginfo_get_count(msginfo) < 4) {
                microkit_dbg_puts("FILE SERVER: incorrect operation parameter count\n");
                // return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            uint32_t write_offset = microkit_mr_get(2);
            size_t write_length = (size_t)microkit_mr_get(3);
            return_code = write_file_operation(channel, file_id, write_offset, write_length);
            break;
        }

        case OP_OPEN:
            microkit_dbg_puts("FILE SERVER: processing open operation\n");
            return_code = open_file_operation(channel);
            break;

        case OP_CLOSE:
            /* code */
            break;

        case OP_DELETE: {
            microkit_dbg_puts("FILE SERVER: processing delete operation\n");
            if (microkit_msginfo_get_count(msginfo) < 2) {
                microkit_dbg_puts("FILE SERVER: incorrect operation parameter count\n");
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = delete_file_operation(channel, file_id);
            break;
        }

        case OP_LIST: {
            microkit_dbg_puts("FILE SERVER: processing list operation\n");
            return_code = list_files_operation(channel);
            break;
        }
            
        case OP_SET_PERMISSIONS: {
            microkit_dbg_puts("FILE SERVER: processing set permissions operation\n");
            if (microkit_msginfo_get_count(msginfo) < 3) {
                microkit_dbg_puts("FILE SERVER: incorrect operation parameter count\n");
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            uint8_t new_permissions = (uint8_t)microkit_mr_get(2);
            return_code = set_file_permissions_operation(channel, file_id, new_permissions);
            break;
        }

        case OP_GET_PERMISSIONS: {
            microkit_dbg_puts("FILE SERVER: processing get permissions operation\n");
            if (microkit_msginfo_get_count(msginfo) < 2) {
                microkit_dbg_puts("FILE SERVER: incorrect operation parameter count\n");
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = get_file_permissions_operation(channel, file_id);
            break;
        }

        case OP_RENAME: {
            microkit_dbg_puts("FILE SERVER: processing rename operation\n");
            if (microkit_msginfo_get_count(msginfo) < 2) {
                microkit_dbg_puts("FILE SERVER: incorrect operation parameter count\n");
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = rename_file_operation(channel, file_id);
            break;
        }

        case OP_GET_FILE_SIZE: {
            microkit_dbg_puts("FILE SERVER: processing get file size operation\n");
            if (microkit_msginfo_get_count(msginfo) < 2) {
                microkit_dbg_puts("FILE SERVER: incorrect operation parameter count\n");
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = get_file_size_operation(channel, file_id);
            break;
        }

        case OP_EXISTS: {
            microkit_dbg_puts("FILE SERVER: processing file exists operation\n");
            return_code = file_exists_operation(channel);
            break;
        }

        case OP_COPY: {
            microkit_dbg_puts("FILE SERVER: processing copy file operation\n");
            if (microkit_msginfo_get_count(msginfo) < 2) {
                microkit_dbg_puts("FILE SERVER: incorrect operation parameter count\n");
                return_code = FS_ERR_INCORRECT_OP_PARAM_COUNT;
                break;
            }
            uint32_t file_id = microkit_mr_get(1);
            return_code = copy_file_operation(channel, file_id);
            break;
        }

        default:
            return_code = FS_ERR_INVALID_OP_CODE;
            break;
    }

    microkit_mr_set(0, return_code);

    return msginfo;
}