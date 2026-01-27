#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


// maybe add a to

bool string_compare(const unsigned char *str1, const unsigned char *str2, size_t max_length) {
    for (size_t i = 0; i < max_length; i++) {
        if (str1[i] != str2[i]) {
            return false;
        }
        if (str1[i] == '\0') {
            break;
        }
    }
    return true;
}