#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../debug_output.h"

#include "benchmark_utils.h"

static size_t append_c_string(unsigned char *dest, size_t offset, size_t capacity, const char *src) {
    size_t index = offset;

    while (*src != '\0' && index + 1 < capacity) {
        dest[index++] = (unsigned char)*src++;
    }

    if (index < capacity) {
        dest[index] = '\0';
    }

    return index;
}

static size_t append_u32(unsigned char *dest, size_t offset, size_t capacity, uint32_t value) {
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

static void make_file_path(unsigned char *dest, size_t capacity,
                           const unsigned char *root_path, uint32_t iteration) {
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

static void fill_pattern(uint8_t *buffer, size_t length, uint32_t seed) {
    for (size_t i = 0; i < length; i++) {
        buffer[i] = (uint8_t)((seed + i) & 0xffu);
    }
}

static int buffers_equal(const uint8_t *lhs, const uint8_t *rhs, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (lhs[i] != rhs[i]) {
            return 0;
        }
    }

    return 1;
}

static bool expect_rc(int rc, const char *operation) {
    if (rc == FS_OK) {
        return true;
    }

    microkit_debug_puts(TEST_VERBOSITY, operation);
    microkit_debug_puts(TEST_VERBOSITY, " failed with rc=");
    microkit_debug_put32(TEST_VERBOSITY, (uint32_t)rc);
    microkit_debug_puts(TEST_VERBOSITY, "\n");
    return false;
}

bool benchmark_run_workload(uint8_t *fs_buffer_base, int channel_id,
                           const unsigned char *root_path, uint32_t seed_base) {
    unsigned char path[96];
    uint8_t write_buffer[BENCHMARK_FILE_SIZE];

    int rc = send_delete_entry_request(root_path, fs_buffer_base, channel_id);
    if (rc != FS_OK && rc != FS_ERR_NOT_FOUND) {
        return expect_rc(rc, "delete benchmark root");
    }

    rc = send_create_directory_request(root_path, PERM_PUBLIC, fs_buffer_base, channel_id);
    if (!expect_rc(rc, "create benchmark root")) {
        return false;
    }

    for (uint32_t iteration = 0; iteration < BENCHMARK_FILE_COUNT; iteration++) {
        make_file_path(path, sizeof(path), root_path, iteration);
        fill_pattern(write_buffer, sizeof(write_buffer), seed_base + iteration * 17u);

        fs_result_fileid_t create_result = send_create_file_request(
            path, PERM_PUBLIC, READ_WRITE_OP, fs_buffer_base, channel_id);
        if (!expect_rc(create_result.rc, "create benchmark file")) {
            return false;
        }

        fs_result_write_t write_result = send_write_file_request(
            create_result.file_id, sizeof(write_buffer), write_buffer, fs_buffer_base, channel_id);
        if (!expect_rc(write_result.rc, "write benchmark file") ||
            write_result.bytes_written != sizeof(write_buffer)) {
            microkit_debug_puts(TEST_VERBOSITY, "write size mismatch\n");
            return false;
        }

        rc = send_seek_file_request(create_result.file_id, 0, channel_id);
        if (!expect_rc(rc, "seek benchmark file")) {
            return false;
        }

        fs_result_read_t read_result = send_read_file_request(
            create_result.file_id, sizeof(write_buffer), fs_buffer_base, channel_id);
        if (!expect_rc(read_result.rc, "read benchmark file") ||
            read_result.bytes_read != sizeof(write_buffer)) {
            microkit_debug_puts(TEST_VERBOSITY, "read size mismatch\n");
            return false;
        }

        if (!buffers_equal(read_result.data_address, write_buffer, sizeof(write_buffer))) {
            microkit_debug_puts(TEST_VERBOSITY, "readback mismatch\n");
            return false;
        }

        rc = send_close_file_request(create_result.file_id, channel_id);
        if (!expect_rc(rc, "close benchmark file")) {
            return false;
        }
    }

    return true;
}

void benchmark_finish(uint8_t *fs_buffer_base, int channel_id, bool success) {
    if (!success) {
        microkit_debug_puts(TEST_VERBOSITY, "benchmark client failed\n");
    }

    mark_client_as_finished_running(fs_buffer_base);
    microkit_notify(channel_id);
    seL4_Yield();
}