#include "../internal.h"

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>

static uint32_t sm4_l(uint32_t x) {
    return x ^ sc_rotl32(x, 2) ^ sc_rotl32(x, 10) ^
           sc_rotl32(x, 18) ^ sc_rotl32(x, 24);
}

__attribute__((target("gfni"), noinline))
static __m128i sm4_sub(__m128i x) {
    const __m128i a1 = _mm_set1_epi64x(INT64_C(0x5d50221ab97d284c));
    const __m128i a2 = _mm_set1_epi64x(INT64_C(0x89b5a674a934abf3));
    x = _mm_gf2p8affine_epi64_epi8(x, a1, 0x3e);
    return _mm_gf2p8affineinv_epi64_epi8(x, a2, 0xd3);
}

__attribute__((target("gfni")))
void sc_x86_sm4_encrypt_gfni(const sc_sm4_key *key, const uint8_t in[16],
                             uint8_t out[16]) {
    uint32_t x[36];
    for (size_t i = 0; i < 4; ++i) x[i] = sc_load_be32(in + 4 * i);
    for (size_t r = 0; r < 32; ++r) {
        uint32_t q = x[r + 1] ^ x[r + 2] ^ x[r + 3] ^ key->rk[r];
        uint8_t b[16] = {
            (uint8_t)(q >> 24),(uint8_t)(q >> 16),(uint8_t)(q >> 8),(uint8_t)q
        };
        __m128i v = sm4_sub(_mm_loadu_si128((const __m128i *)(const void *)b));
        _mm_storeu_si128((__m128i *)(void *)b, v);
        x[r + 4] = x[r] ^ sm4_l(sc_load_be32(b));
    }
    for (size_t i = 0; i < 4; ++i) sc_store_be32(out + 4 * i, x[35U - i]);
}

__attribute__((target("gfni")))
void sc_x86_sm4_encrypt4_gfni(const sc_sm4_key *key, const uint8_t in[64],
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
#define ROTL(v,n) _mm_or_si128(_mm_slli_epi32((v),(n)), \
                               _mm_srli_epi32((v),32-(n)))
        __m128i l = _mm_xor_si128(
            _mm_xor_si128(b, ROTL(b,2)),
            _mm_xor_si128(ROTL(b,10),
                          _mm_xor_si128(ROTL(b,18), ROTL(b,24))));
#undef ROTL
        x[r + 4] = _mm_xor_si128(x[r], l);
    }
    for (size_t w = 0; w < 4; ++w) {
        _mm_storeu_si128((__m128i *)(void *)words, x[35U - w]);
        for (size_t lane = 0; lane < 4; ++lane)
            sc_store_be32(out + 16 * lane + 4 * w, words[lane]);
    }
}

#else
void sc_x86_sm4_encrypt_gfni(const sc_sm4_key *key, const uint8_t in[16],
                             uint8_t out[16]) {
    sc_sm4_encrypt_ref(key, in, out);
}
void sc_x86_sm4_encrypt4_gfni(const sc_sm4_key *key, const uint8_t in[64],
                              uint8_t out[64]) {
    for (size_t i = 0; i < 4; ++i)
        sc_sm4_encrypt_ref(key, in + 16 * i, out + 16 * i);
}
#endif
