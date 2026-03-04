#pragma once

#include <stdint.h>
#include <microkit.h>

#define VERBOSE 0

static inline void microkit_debug_puts(const char *s)
{
    if (VERBOSE) {
        microkit_dbg_puts(s);
    }
}

static inline void microkit_debug_put32(uint32_t n)
{
    if (VERBOSE) {
        microkit_dbg_put32(n);
    }
}

static inline void microkit_debug_putc(int c)
{
    if (VERBOSE) {
        microkit_dbg_putc(c);
    }
}