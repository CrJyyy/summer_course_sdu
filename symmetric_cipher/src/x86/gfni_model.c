#include "../internal.h"

static uint8_t parity8(uint8_t x) {
    x ^= (uint8_t)(x >> 4);
    x ^= (uint8_t)(x >> 2);
    x ^= (uint8_t)(x >> 1);
    return (uint8_t)(x & 1U);
}

static uint8_t affine(uint8_t x, const uint8_t rows[8], uint8_t c) {
    uint8_t y = 0;
    for (unsigned r = 0; r < 8; ++r)
        y |= (uint8_t)(parity8((uint8_t)(x & rows[r])) << r);
    return (uint8_t)(y ^ c);
}

static uint8_t gf_aes_mul(uint8_t a, uint8_t b) {
    uint8_t y = 0;
    for (unsigned i = 0; i < 8; ++i) {
        y ^= (uint8_t)(a & (uint8_t)(0U - (b & 1U)));
        uint8_t high = (uint8_t)(a >> 7);
        a = (uint8_t)((a << 1) ^ (0x1bU & (uint8_t)(0U - high)));
        b >>= 1;
    }
    return y;
}

static uint8_t gf_aes_inverse(uint8_t x) {
    if (x == 0) return 0;
    uint8_t y = 1, p = x;
    unsigned exponent = 254;
    while (exponent) {
        if (exponent & 1U) y = gf_aes_mul(y, p);
        p = gf_aes_mul(p, p);
        exponent >>= 1;
    }
    return y;
}

uint8_t sc_sm4_gfni_scalar_model(uint8_t x) {
    /* Guo 2022, Eq. (12): Y=A1*X+C1; S=A2*Y^-1+C. */
    static const uint8_t a1[8] = {
        0x4c,0x28,0x7d,0xb9,0x1a,0x22,0x50,0x5d
    };
    static const uint8_t a2[8] = {
        0xf3,0xab,0x34,0xa9,0x74,0xa6,0xb5,0x89
    };
    uint8_t y = affine(x, a1, 0x3e);
    return affine(gf_aes_inverse(y), a2, 0xd3);
}
