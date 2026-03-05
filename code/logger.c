#include <microkit.h>

void notified(microkit_channel ch) {}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo) {
    if (microkit_mr_get(0) == 0) {
        microkit_dbg_put32(microkit_mr_get(1));
    } else {
        microkit_dbg_putc(microkit_mr_get(1));
    }
    return msginfo;
}

void init(void) {
    microkit_debug_puts("Logger initialized\n");
}

