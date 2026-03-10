#include <microkit.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "debug_output.h"

#include "test_common.h"

void output_suite_pass(unsigned char *msg) {
	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_GREEN);
	microkit_debug_puts(TEST_VERBOSITY, "\n===== [SUITE PASS] ");
	microkit_debug_puts(TEST_VERBOSITY, (const char *)msg);
	microkit_debug_puts(TEST_VERBOSITY, " =====\n");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
}

void output_pass(unsigned char *msg) {
	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_GREEN);
	microkit_debug_puts(TEST_VERBOSITY, "[PASS] ");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
	microkit_debug_puts(TEST_VERBOSITY, (const char *)msg);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
}

void output_fail(unsigned char *msg) {
	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
	microkit_debug_puts(TEST_VERBOSITY, "\n===== [SUITE FAIL] ");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
	microkit_debug_puts(TEST_VERBOSITY, (const char *)msg);
	microkit_debug_puts(TEST_VERBOSITY, " =====\n");
}

int expect_eq_int(int actual, int expected, const char *name) {
	if (actual == expected) {
		return 1;
	}

	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
	microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
	microkit_debug_puts(TEST_VERBOSITY, name);
	microkit_debug_puts(TEST_VERBOSITY, ": expected ");
	microkit_debug_put32(TEST_VERBOSITY, (uint32_t)expected);
	microkit_debug_puts(TEST_VERBOSITY, " but got ");
	microkit_debug_put32(TEST_VERBOSITY, (uint32_t)actual);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
	return 0;
}

int expect_not_eq_int(int actual, int not_expected, const char *name) {
	if (actual != not_expected) {
		return 1;
	}

	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
	microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
	microkit_debug_puts(TEST_VERBOSITY, name);
	microkit_debug_puts(TEST_VERBOSITY, ": did not expect ");
	microkit_debug_put32(TEST_VERBOSITY, (uint32_t)not_expected);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
	return 0;
}

int expect_eq_uint32(uint32_t actual, uint32_t expected, const char *name) {
	if (actual == expected) {
		return 1;
	}

	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
	microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
	microkit_debug_puts(TEST_VERBOSITY, name);
	microkit_debug_puts(TEST_VERBOSITY, ": expected ");
	microkit_debug_put32(TEST_VERBOSITY, expected);
	microkit_debug_puts(TEST_VERBOSITY, " but got ");
	microkit_debug_put32(TEST_VERBOSITY, actual);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
	return 0;
}

int expect_eq_uint8(uint8_t actual, uint8_t expected, const char *name) {
	if (actual == expected) {
		return 1;
	}

	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
	microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
	microkit_debug_puts(TEST_VERBOSITY, name);
	microkit_debug_puts(TEST_VERBOSITY, ": expected ");
	microkit_debug_put32(TEST_VERBOSITY, (uint32_t)expected);
	microkit_debug_puts(TEST_VERBOSITY, " but got ");
	microkit_debug_put32(TEST_VERBOSITY, (uint32_t)actual);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
	return 0;
}

int expect_true(bool cond, const char *name) {
	if (cond) {
		return 1;
	}

	seL4_Yield();
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
	microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
	microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
	microkit_debug_puts(TEST_VERBOSITY, name);
	microkit_debug_puts(TEST_VERBOSITY, "\n");
	return 0;
}

int expect_equal_to_buffer(const uint8_t *actual, const uint8_t *expected, size_t length, const char *test_message) {
	for (size_t i = 0; i < length; i++) {
		if (actual[i] != expected[i]) {
			seL4_Yield();
			microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
			microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
			microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
			microkit_debug_puts(TEST_VERBOSITY, test_message);
			microkit_debug_puts(TEST_VERBOSITY, ": Expected: ");
			for (size_t j = 0; j < length; j++) {
				microkit_debug_putc(TEST_VERBOSITY, ((const char *)expected)[j]);
				if (((const char *)expected)[j] == '\0') {
					microkit_debug_putc(TEST_VERBOSITY, ',');
				}
			}
			microkit_debug_puts(TEST_VERBOSITY, ", Got: ");
			for (size_t j = 0; j < length; j++) {
				microkit_debug_putc(TEST_VERBOSITY, ((const char *)actual)[j]);
				if (((const char *)actual)[j] == '\0') {
					microkit_debug_putc(TEST_VERBOSITY, ',');
				}
			}
			microkit_debug_puts(TEST_VERBOSITY, "\n");
			return 0;
		}
	}

	return 1;
}

int expect_eq_strings(const char *actual, const char *expected, const char *test_message) {
	size_t i = 0;
	while (actual[i] != '\0' && expected[i] != '\0') {
		if (actual[i] != expected[i]) {
			seL4_Yield();
			microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
			microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
			microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
			microkit_debug_puts(TEST_VERBOSITY, test_message);
			microkit_debug_puts(TEST_VERBOSITY, ": Expected: ");
			microkit_debug_puts(TEST_VERBOSITY, expected);
			microkit_debug_puts(TEST_VERBOSITY, ", Got: ");
			microkit_debug_puts(TEST_VERBOSITY, actual);
			microkit_debug_puts(TEST_VERBOSITY, "\n");
			return 0;
		}
		i++;
	}

	if (actual[i] != expected[i]) {
		seL4_Yield();
		microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RED);
		microkit_debug_puts(TEST_VERBOSITY, "[ERROR] ");
		microkit_debug_puts(TEST_VERBOSITY, ANSI_COLOR_RESET);
		microkit_debug_puts(TEST_VERBOSITY, test_message);
		microkit_debug_puts(TEST_VERBOSITY, ": Expected: ");
		microkit_debug_puts(TEST_VERBOSITY, expected);
		microkit_debug_puts(TEST_VERBOSITY, ", Got: ");
		microkit_debug_puts(TEST_VERBOSITY, actual);
		microkit_debug_puts(TEST_VERBOSITY, "\n");
		return 0;
	}

	return 1;
}