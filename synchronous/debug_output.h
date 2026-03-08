#pragma once

#include <stdint.h>
#include <microkit.h>

#define VERBOSITY_LEVEL 1
#define TEST_VERBOSITY 1
#define OUTPUT_VERBOSITY 2

static inline void microkit_debug_puts(uint8_t verbosity, const char *s) {
    if (verbosity <= VERBOSITY_LEVEL) {
        microkit_dbg_puts(s);
    }
}

static inline void microkit_debug_put32(uint8_t verbosity, uint32_t n) {
    if (verbosity <= VERBOSITY_LEVEL) {
        microkit_dbg_put32(n);
    }
}

static inline void microkit_debug_putc(uint8_t verbosity, int c) {
    if (verbosity <= VERBOSITY_LEVEL) {
        microkit_dbg_putc(c);
    }
}
