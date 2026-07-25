#include "internal.h"

uint32_t sc_load_be32(const uint8_t p[4]) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void sc_store_be32(uint8_t p[4], uint32_t x) {
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

uint64_t sc_load_be64(const uint8_t p[8]) {
    return ((uint64_t)sc_load_be32(p) << 32) | sc_load_be32(p + 4);
}

void sc_store_be64(uint8_t p[8], uint64_t x) {
    sc_store_be32(p, (uint32_t)(x >> 32));
    sc_store_be32(p + 4, (uint32_t)x);
}

uint32_t sc_rotl32(uint32_t x, unsigned n) {
    n &= 31U;
    return (x << n) | (x >> ((32U - n) & 31U));
}
