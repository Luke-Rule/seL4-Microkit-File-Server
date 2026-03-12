#include <microkit.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// cycle reg counting for benchmarking timings

static inline uint64_t read_cntvct(void) {
    uint64_t val;
    asm volatile("isb sy" : : : "memory");
    asm volatile("mrs %0, cntpct_el0" : "=r"(val));
    return val;
}

static inline uint64_t read_cntfrq(void) {
    uint64_t val;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(val));
    return val;
}

// printing times

static inline void microkit_dbg_putu64(uint64_t x) {
    char buf[21];
    unsigned i = 0;

    if (x == 0) {
        microkit_dbg_putc('0');
        return;
    }

    while (x > 0 && i < sizeof(buf)) {
        buf[i++] = '0' + (x % 10);
        x /= 10;
    }

    while (i > 0) {
        microkit_dbg_putc(buf[--i]);
    }
}

static inline void microkit_dbg_putu32_6(uint32_t x)
{
    char buf[6];
    for (int i = 5; i >= 0; i--) {
        buf[i] = '0' + (x % 10);
        x /= 10;
    }
    for (int i = 0; i < 6; i++) {
        microkit_dbg_putc(buf[i]);
    }
}