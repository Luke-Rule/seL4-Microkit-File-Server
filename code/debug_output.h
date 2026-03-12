#pragma once

#include <stdint.h>
#include <microkit.h>

#define VERBOSITY_LEVEL 1
#define TEST_VERBOSITY 1
#define OUTPUT_VERBOSITY 2

// wrappers to allow toggling debug output
// when writing long strings, it is recommended to first call sel4_Yield() first, 
// to ensure maximum scheduling time for printing, to avoid chopped output
// this is not placed within the wrappers, as some desired prints span multiple calls

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
