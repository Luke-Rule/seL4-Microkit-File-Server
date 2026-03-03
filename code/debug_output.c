#include "debug_output.h"
#include "microkit.h"

void microkit_debug_puts(const unsigned char *s) {
    if (VERBOSE) {
        microkit_dbg_puts(s);
    }
}

void microkit_debug_put32(uint32_t n) {
    if (VERBOSE) {
        microkit_dbg_put32(n);
    }
}

void microkit_debug_putc(char c) {
    if (VERBOSE) {
        microkit_dbg_putc(c);
    }
}