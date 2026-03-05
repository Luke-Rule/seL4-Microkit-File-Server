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

// static inline void microkit_debug_puts(uint8_t channel, const char *s)
// {
//     if (VERBOSE) {
//         for (size_t i = 0; i < 100 && s[i] != '\0'; i++) {
//             microkit_msginfo msg = microkit_msginfo_new(0, 2);
//             microkit_mr_set(0, 1);
//             microkit_mr_set(1, s[i]);
//             microkit_ppcall(channel, msg);
//         }
//     }
// }

// static inline void microkit_debug_put32(uint8_t channel, uint32_t n)
// {
//     if (VERBOSE) {
//         microkit_msginfo msg = microkit_msginfo_new(0, 2);
//         microkit_mr_set(0, 0);
//         microkit_mr_set(1, n);
//         microkit_ppcall(channel, msg);
//     }
// }

// static inline void microkit_debug_putc(uint8_t channel, int c)
// {
//     if (VERBOSE) {
//         microkit_msginfo msg = microkit_msginfo_new(0, 2);
//         microkit_mr_set(0, 1);
//         microkit_mr_set(1, c);
//         microkit_ppcall(channel, msg);
//     }
// }