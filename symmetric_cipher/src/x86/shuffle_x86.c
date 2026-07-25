#include "../internal.h"

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>

static const uint8_t sm4_rows[16][16] = {
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

__attribute__((target("ssse3")))
static __m128i sm4_sub(__m128i x) {
    __m128i lo = _mm_and_si128(x, _mm_set1_epi8(15));
    __m128i hi = _mm_and_si128(_mm_srli_epi16(x, 4), _mm_set1_epi8(15));
    __m128i y = _mm_setzero_si128();
    for (int row = 0; row < 16; ++row) {
        __m128i table = _mm_loadu_si128(
            (const __m128i *)(const void *)sm4_rows[row]);
        __m128i candidate = _mm_shuffle_epi8(table, lo);
        __m128i mask = _mm_cmpeq_epi8(hi, _mm_set1_epi8((char)row));
        y = _mm_or_si128(y, _mm_and_si128(candidate, mask));
    }
    return y;
}

__attribute__((target("ssse3")))
void sc_x86_sm4_encrypt4_shuffle(const sc_sm4_key *key, const uint8_t in[64],
                                  uint8_t out[64]) {
    uint32_t words[4];
    __m128i x[36];
    for (size_t w = 0; w < 4; ++w) {
        for (size_t lane = 0; lane < 4; ++lane)
            words[lane] = sc_load_be32(in + 16 * lane + 4 * w);
        x[w] = _mm_loadu_si128((const __m128i *)(const void *)words);
    }
    for (size_t r = 0; r < 32; ++r) {
        __m128i q = _mm_xor_si128(
            _mm_xor_si128(x[r + 1], x[r + 2]),
            _mm_xor_si128(x[r + 3], _mm_set1_epi32((int)key->rk[r])));
        __m128i b = sm4_sub(q);
#define ROTL32(v, n) _mm_or_si128(_mm_slli_epi32((v), (n)), \
                                  _mm_srli_epi32((v), 32 - (n)))
        __m128i linear = _mm_xor_si128(
            _mm_xor_si128(b, ROTL32(b, 2)),
            _mm_xor_si128(ROTL32(b, 10),
                          _mm_xor_si128(ROTL32(b, 18), ROTL32(b, 24))));
#undef ROTL32
        x[r + 4] = _mm_xor_si128(x[r], linear);
    }
    for (size_t w = 0; w < 4; ++w) {
        _mm_storeu_si128((__m128i *)(void *)words, x[35U - w]);
        for (size_t lane = 0; lane < 4; ++lane)
            sc_store_be32(out + 16 * lane + 4 * w, words[lane]);
    }
}

__attribute__((target("ssse3")))
void sc_x86_twine_crypt4_shuffle(const sc_twine_key *key,
                                  const uint8_t in[32], uint8_t out[32],
                                  int decrypt) {
    static const uint8_t box_bytes[16] =
        {12,0,15,10,2,11,9,5,8,3,13,7,1,14,6,4};
    static const uint8_t gather_bytes[16] =
        {0x80,0,0x80,2,0x80,4,0x80,6,0x80,8,0x80,10,0x80,12,0x80,14};
    static const uint8_t enc_perm[16] =
        {1,2,11,6,3,0,9,4,7,10,13,14,5,8,15,12};
    static const uint8_t dec_perm[16] =
        {5,0,1,4,7,12,3,8,13,6,9,2,15,10,11,14};
    uint8_t n[4][16], kb[16];
    __m128i x[4];
    for (size_t lane = 0; lane < 4; ++lane) {
        for (size_t i = 0; i < 8; ++i) {
            n[lane][2 * i] = (uint8_t)(in[8 * lane + i] >> 4);
            n[lane][2 * i + 1] = (uint8_t)(in[8 * lane + i] & 15);
        }
        x[lane] = _mm_loadu_si128((const __m128i *)(const void *)n[lane]);
    }
    __m128i box = _mm_loadu_si128((const __m128i *)(const void *)box_bytes);
    __m128i gather =
        _mm_loadu_si128((const __m128i *)(const void *)gather_bytes);
    __m128i perm = _mm_loadu_si128((const __m128i *)(const void *)
                                   (decrypt ? dec_perm : enc_perm));
    __m128i odd = _mm_set1_epi16((short)0xff00);
    for (size_t step = 0; step < 36; ++step) {
        size_t r = decrypt ? 35U - step : step;
        memset(kb, 0, sizeof(kb));
        for (size_t j = 0; j < 8; ++j) kb[2 * j + 1] = key->rk[r][j];
        __m128i kv = _mm_loadu_si128((const __m128i *)(const void *)kb);
        for (size_t lane = 0; lane < 4; ++lane) {
            __m128i lookup = _mm_xor_si128(_mm_shuffle_epi8(x[lane], gather), kv);
            x[lane] = _mm_xor_si128(
                x[lane], _mm_and_si128(_mm_shuffle_epi8(box, lookup), odd));
            if (step != 35) x[lane] = _mm_shuffle_epi8(x[lane], perm);
        }
    }
    for (size_t lane = 0; lane < 4; ++lane) {
        _mm_storeu_si128((__m128i *)(void *)n[lane], x[lane]);
        for (size_t i = 0; i < 8; ++i)
            out[8 * lane + i] =
                (uint8_t)((n[lane][2 * i] << 4) | n[lane][2 * i + 1]);
    }
}

#else
void sc_x86_sm4_encrypt4_shuffle(const sc_sm4_key *key, const uint8_t in[64],
                                  uint8_t out[64]) {
    for (size_t i = 0; i < 4; ++i)
        sc_sm4_encrypt_ref(key, in + 16 * i, out + 16 * i);
}
void sc_x86_twine_crypt4_shuffle(const sc_twine_key *key,
                                  const uint8_t in[32], uint8_t out[32],
                                  int decrypt) {
    for (size_t i = 0; i < 4; ++i) {
        if (decrypt) sc_twine_decrypt(key, in + 8 * i, out + 8 * i);
        else sc_twine_encrypt(key, in + 8 * i, out + 8 * i);
    }
}
#endif
