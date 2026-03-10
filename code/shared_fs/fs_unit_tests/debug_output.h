#pragma once

#include <stdint.h>

#define VERBOSITY_LEVEL 1
#define TEST_VERBOSITY 1
#define OUTPUT_VERBOSITY 2

static inline void microkit_debug_puts(uint8_t verbosity, const char *s) {
    verbosity = verbosity;
    s = s;
    
    return;
}

static inline void microkit_debug_put32(uint8_t verbosity, uint32_t n) {
    verbosity = verbosity;
    n = n;

    return;
}

static inline void microkit_debug_putc(uint8_t verbosity, int c) {
    verbosity = verbosity;
    c = c;

    return;
}
