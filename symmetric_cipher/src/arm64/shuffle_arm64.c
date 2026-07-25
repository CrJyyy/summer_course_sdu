#include "../internal.h"

#if defined(__aarch64__) || defined(__arm64__)
#include <arm_neon.h>

static const uint8_t twine_sbox[16] = {
    0x0c,0x00,0x0f,0x0a,0x02,0x0b,0x09,0x05,
    0x08,0x03,0x0d,0x07,0x01,0x0e,0x06,0x04
};

static const uint8_t twine_inv_perm[16] = {
    1,2,11,6,3,0,9,4,7,10,13,14,5,8,15,12
};

void sc_arm_twine_encrypt_shuffle(const sc_twine_key *key, const uint8_t in[8],
                                  uint8_t out[8]) {
    uint8_t n[16], k[16], idx_bytes[16] = {
        16,0,16,2,16,4,16,6,16,8,16,10,16,12,16,14
    };
    for (size_t i = 0; i < 8; ++i) {
        n[2 * i] = (uint8_t)(in[i] >> 4);
        n[2 * i + 1] = (uint8_t)(in[i] & 15);
    }
    uint8x16_t x = vld1q_u8(n);
    uint8x16_t box = vld1q_u8(twine_sbox);
    uint8x16_t gather_even = vld1q_u8(idx_bytes);
    uint8x16_t p = vld1q_u8(twine_inv_perm);
    uint8x16_t odd_mask = vreinterpretq_u8_u16(vdupq_n_u16(0xff00));
    for (size_t r = 0; r < 36; ++r) {
        memset(k, 0, sizeof(k));
        for (size_t j = 0; j < 8; ++j) k[2 * j + 1] = key->rk[r][j];
        uint8x16_t lookup = veorq_u8(vqtbl1q_u8(x, gather_even), vld1q_u8(k));
        x = veorq_u8(x, vandq_u8(vqtbl1q_u8(box, lookup), odd_mask));
        if (r != 35) x = vqtbl1q_u8(x, p);
    }
    vst1q_u8(n, x);
    for (size_t i = 0; i < 8; ++i)
        out[i] = (uint8_t)((n[2 * i] << 4) | n[2 * i + 1]);
}

void sc_arm_twine_crypt4_shuffle(const sc_twine_key *key, const uint8_t in[32],
                                 uint8_t out[32], int decrypt) {
    uint8_t n[4][16], k[16], idx_bytes[16] = {
        16,0,16,2,16,4,16,6,16,8,16,10,16,12,16,14
    };
    uint8x16_t x[4];
    for (size_t lane = 0; lane < 4; ++lane) {
        for (size_t i = 0; i < 8; ++i) {
            n[lane][2 * i] = (uint8_t)(in[8 * lane + i] >> 4);
            n[lane][2 * i + 1] = (uint8_t)(in[8 * lane + i] & 15);
        }
        x[lane] = vld1q_u8(n[lane]);
    }
    uint8x16_t box = vld1q_u8(twine_sbox);
    uint8x16_t gather_even = vld1q_u8(idx_bytes);
    uint8x16_t p = vld1q_u8(twine_inv_perm);
    static const uint8_t forward_perm[16] = {
        5,0,1,4,7,12,3,8,13,6,9,2,15,10,11,14
    };
    uint8x16_t fp = vld1q_u8(forward_perm);
    uint8x16_t odd_mask = vreinterpretq_u8_u16(vdupq_n_u16(0xff00));
    for (size_t step = 0; step < 36; ++step) {
        size_t r = decrypt ? 35U - step : step;
        memset(k, 0, sizeof(k));
        for (size_t j = 0; j < 8; ++j) k[2 * j + 1] = key->rk[r][j];
        uint8x16_t kv = vld1q_u8(k);
        for (size_t lane = 0; lane < 4; ++lane) {
            uint8x16_t lookup =
                veorq_u8(vqtbl1q_u8(x[lane], gather_even), kv);
            x[lane] = veorq_u8(
                x[lane], vandq_u8(vqtbl1q_u8(box, lookup), odd_mask));
            if (step != 35)
                x[lane] = vqtbl1q_u8(x[lane], decrypt ? fp : p);
        }
    }
    for (size_t lane = 0; lane < 4; ++lane) {
        vst1q_u8(n[lane], x[lane]);
        for (size_t i = 0; i < 8; ++i)
            out[8 * lane + i] =
                (uint8_t)((n[lane][2 * i] << 4) | n[lane][2 * i + 1]);
    }
}

static const uint8_t sm4_sbox_rows[16][16] = {
    {0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
    {0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
    {0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
    {0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
    {0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
    {0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
    {0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
    {0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
    {0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
    {0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
    {0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
    {0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
    {0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
    {0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
    {0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
    {0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};

static uint8x16_t sm4_sub_bytes(uint8x16_t x) {
    uint8x16_t lo = vandq_u8(x, vdupq_n_u8(15));
    uint8x16_t hi = vshrq_n_u8(x, 4);
    uint8x16_t y = vdupq_n_u8(0);
    for (uint8_t row = 0; row < 16; ++row) {
        uint8x16_t candidate = vqtbl1q_u8(vld1q_u8(sm4_sbox_rows[row]), lo);
        uint8x16_t mask = vceqq_u8(hi, vdupq_n_u8(row));
        y = vorrq_u8(y, vandq_u8(candidate, mask));
    }
    return y;
}

static uint32_t sm4_l(uint32_t x) {
    return x ^ sc_rotl32(x, 2) ^ sc_rotl32(x, 10) ^
           sc_rotl32(x, 18) ^ sc_rotl32(x, 24);
}

void sc_arm_sm4_encrypt_shuffle(const sc_sm4_key *key, const uint8_t in[16],
                                uint8_t out[16]) {
    uint32_t x[36];
    for (size_t i = 0; i < 4; ++i) x[i] = sc_load_be32(in + 4 * i);
    for (size_t r = 0; r < 32; ++r) {
        uint32_t q = x[r + 1] ^ x[r + 2] ^ x[r + 3] ^ key->rk[r];
        uint8_t bytes[16] = {
            (uint8_t)(q >> 24),(uint8_t)(q >> 16),(uint8_t)(q >> 8),(uint8_t)q
        };
        uint8x16_t sub = sm4_sub_bytes(vld1q_u8(bytes));
        vst1q_u8(bytes, sub);
        uint32_t b = sc_load_be32(bytes);
        x[r + 4] = x[r] ^ sm4_l(b);
    }
    for (size_t i = 0; i < 4; ++i) sc_store_be32(out + 4 * i, x[35U - i]);
}

static uint32x4_t rotlq32(uint32x4_t x, int n) {
    return vorrq_u32(vshlq_u32(x, vdupq_n_s32(n)),
                     vshlq_u32(x, vdupq_n_s32(n - 32)));
}

void sc_arm_sm4_encrypt4_shuffle(const sc_sm4_key *key, const uint8_t in[64],
                                 uint8_t out[64]) {
    uint32_t words[4];
    uint32x4_t x[36];
    for (size_t w = 0; w < 4; ++w) {
        for (size_t lane = 0; lane < 4; ++lane)
            words[lane] = sc_load_be32(in + 16 * lane + 4 * w);
        x[w] = vld1q_u32(words);
    }
    for (size_t r = 0; r < 32; ++r) {
        uint32x4_t q = veorq_u32(
            veorq_u32(x[r + 1], x[r + 2]),
            veorq_u32(x[r + 3], vdupq_n_u32(key->rk[r])));
        uint32x4_t b = vreinterpretq_u32_u8(
            sm4_sub_bytes(vreinterpretq_u8_u32(q)));
        uint32x4_t linear = veorq_u32(
            veorq_u32(b, rotlq32(b, 2)),
            veorq_u32(rotlq32(b, 10),
                      veorq_u32(rotlq32(b, 18), rotlq32(b, 24))));
        x[r + 4] = veorq_u32(x[r], linear);
    }
    for (size_t w = 0; w < 4; ++w) {
        vst1q_u32(words, x[35U - w]);
        for (size_t lane = 0; lane < 4; ++lane)
            sc_store_be32(out + 16 * lane + 4 * w, words[lane]);
    }
}

#else
void sc_arm_twine_encrypt_shuffle(const sc_twine_key *key, const uint8_t in[8],
                                  uint8_t out[8]) {
    sc_twine_encrypt(key, in, out);
}

void sc_arm_sm4_encrypt_shuffle(const sc_sm4_key *key, const uint8_t in[16],
                                uint8_t out[16]) {
    sc_sm4_encrypt_ref(key, in, out);
}
void sc_arm_twine_crypt4_shuffle(const sc_twine_key *key, const uint8_t in[32],
                                 uint8_t out[32], int decrypt) {
    for (size_t i = 0; i < 4; ++i) {
        if (decrypt) sc_twine_decrypt(key, in + 8 * i, out + 8 * i);
        else sc_twine_encrypt(key, in + 8 * i, out + 8 * i);
    }
}
void sc_arm_sm4_encrypt4_shuffle(const sc_sm4_key *key, const uint8_t in[64],
                                 uint8_t out[64]) {
    for (size_t i = 0; i < 4; ++i)
        sc_sm4_encrypt_ref(key, in + 16 * i, out + 16 * i);
}
#endif
