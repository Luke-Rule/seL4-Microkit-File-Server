#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
// TODO use bools
#include "fs_shared.h"

#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

typedef bool (*test_fn_t)(void);

void test_suite_begin(char *msg, client_t *client_data);
void test_begin(char *msg);
bool get_completion(completion_queue_entry_t *out, const char *step_name, client_t *client_data);
bool delete_entry_allow_missing(const unsigned char *path, const char *step_name, client_t *client_data);
bool ensure_clean_test_root(client_t *client_data);
void output_pass(unsigned char *msg);
void output_fail(unsigned char *msg);
void run_test_suite(const char *name, test_fn_t test, client_t *client_data);

int expect_eq_int(int actual, int expected, const char *name);
int expect_not_eq_int(int actual, int not_expected, const char *name);
int expect_eq_uint32(uint32_t actual, uint32_t expected, const char *name);
int expect_eq_uint8(uint8_t actual, uint8_t expected, const char *name);
int expect_true(bool cond, const char *name);

int expect_equal_to_client_buffer(
    const unsigned char *expected,
    size_t length,
    const char *test_message,
    int buffer_index,
    client_t *client_data
);

int expect_equal_to_buffer(
    const uint8_t *actual,
    const uint8_t *expected,
    size_t length,
    const char *test_message
);

int expect_eq_strings(const char *actual, const char *expected, const char *test_message);
