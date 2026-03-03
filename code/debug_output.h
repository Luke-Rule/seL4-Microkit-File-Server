#pragma once

#include <stdint.h>
#include <stddef.h>

#define VERBOSE 1

void microkit_debug_puts(const unsigned char *s);
void microkit_debug_put32(uint32_t n);
void microkit_debug_putc(char c);