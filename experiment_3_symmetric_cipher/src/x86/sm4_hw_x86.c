#include "../internal.h"

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>

__attribute__((target("avx2,sm4")))
void sc_x86_sm4_encrypt8_hw(const sc_sm4_key *key, const uint8_t in[128],
                            uint8_t out[128]) {
    __m256i s[4];
    for (size_t i = 0; i < 4; ++i)
        s[i] = _mm256_loadu_si256(
            (const __m256i *)(const void *)(in + 32 * i));
    for (size_t r = 0; r < 32; r += 4) {
        __m128i k = _mm_loadu_si128(
            (const __m128i *)(const void *)(key->rk + r));
        __m256i rk = _mm256_broadcastsi128_si256(k);
        for (size_t i = 0; i < 4; ++i) s[i] = _mm256_sm4rnds4_epi32(s[i], rk);
    }
    for (size_t i = 0; i < 4; ++i)
        _mm256_storeu_si256((__m256i *)(void *)(out + 32 * i), s[i]);
}

__attribute__((target("avx2,sm4"), noinline))
void sc_x86_sm4_key4_hw(const uint32_t in[4], const uint32_t ck[4],
                         uint32_t out[4]) {
    __m128i x = _mm_loadu_si128((const __m128i *)(const void *)in);
    __m128i c = _mm_loadu_si128((const __m128i *)(const void *)ck);
    _mm_storeu_si128((__m128i *)(void *)out, _mm_sm4key4_epi32(x, c));
}

#else
void sc_x86_sm4_encrypt8_hw(const sc_sm4_key *key, const uint8_t in[128],
                            uint8_t out[128]) {
    for (size_t i = 0; i < 8; ++i)
        sc_sm4_encrypt_ref(key, in + 16 * i, out + 16 * i);
}
void sc_x86_sm4_key4_hw(const uint32_t in[4], const uint32_t ck[4],
                         uint32_t out[4]) {
    (void)ck;
    memcpy(out, in, 16);
}
#endif
