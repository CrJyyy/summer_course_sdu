#include "../internal.h"

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>

static uint64_t reverse64(uint64_t x) {
    x = ((x & UINT64_C(0x5555555555555555)) << 1) |
        ((x >> 1) & UINT64_C(0x5555555555555555));
    x = ((x & UINT64_C(0x3333333333333333)) << 2) |
        ((x >> 2) & UINT64_C(0x3333333333333333));
    x = ((x & UINT64_C(0x0f0f0f0f0f0f0f0f)) << 4) |
        ((x >> 4) & UINT64_C(0x0f0f0f0f0f0f0f0f));
    x = ((x & UINT64_C(0x00ff00ff00ff00ff)) << 8) |
        ((x >> 8) & UINT64_C(0x00ff00ff00ff00ff));
    x = ((x & UINT64_C(0x0000ffff0000ffff)) << 16) |
        ((x >> 16) & UINT64_C(0x0000ffff0000ffff));
    return (x << 32) | (x >> 32);
}

__attribute__((target("pclmul"), noinline))
static void multiply_pclmul(__m128i a, __m128i b, __m128i products[3]) {
    products[0] = _mm_clmulepi64_si128(a, b, 0x00);
    products[1] = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i ax = _mm_xor_si128(a, _mm_shuffle_epi32(a, 0x4e));
    __m128i bx = _mm_xor_si128(b, _mm_shuffle_epi32(b, 0x4e));
    products[2] = _mm_clmulepi64_si128(ax, bx, 0x00);
}

__attribute__((target("avx2,vpclmulqdq"), noinline))
static void multiply_vpclmul(__m128i a, __m128i b, __m128i products[3]) {
    __m256i av = _mm256_broadcastsi128_si256(a);
    __m256i bv = _mm256_broadcastsi128_si256(b);
    products[0] = _mm256_castsi256_si128(_mm256_clmulepi64_epi128(av, bv, 0x00));
    products[1] = _mm256_castsi256_si128(_mm256_clmulepi64_epi128(av, bv, 0x11));
    __m256i ax = _mm256_xor_si256(av, _mm256_shuffle_epi32(av, 0x4e));
    __m256i bx = _mm256_xor_si256(bv, _mm256_shuffle_epi32(bv, 0x4e));
    products[2] = _mm256_castsi256_si128(
        _mm256_clmulepi64_epi128(ax, bx, 0x00));
}

__attribute__((target("pclmul")))
int sc_x86_ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    sc_cpu_features features = sc_detect_cpu_features();
    if (!features.x86_pclmul) return 0;
    uint64_t al = reverse64(sc_load_be64(x));
    uint64_t ah = reverse64(sc_load_be64(x + 8));
    uint64_t bl = reverse64(sc_load_be64(h));
    uint64_t bh = reverse64(sc_load_be64(h + 8));
    __m128i a = _mm_set_epi64x((long long)ah, (long long)al);
    __m128i b = _mm_set_epi64x((long long)bh, (long long)bl);
    __m128i p[3];
    if (features.x86_vpclmul && features.x86_avx2)
        multiply_vpclmul(a, b, p);
    else
        multiply_pclmul(a, b, p);
    uint64_t p0[2], p1[2], pc[2];
    _mm_storeu_si128((__m128i *)(void *)p0, p[0]);
    _mm_storeu_si128((__m128i *)(void *)p1, p[1]);
    _mm_storeu_si128((__m128i *)(void *)pc, p[2]);
    uint64_t cross0 = pc[0] ^ p0[0] ^ p1[0];
    uint64_t cross1 = pc[1] ^ p0[1] ^ p1[1];
    uint64_t z0 = p0[0];
    uint64_t z1 = p0[1] ^ cross0;
    uint64_t h0 = p1[0] ^ cross1;
    uint64_t h1 = p1[1];
    uint64_t q = (h1 >> 63) ^ (h1 >> 62) ^ (h1 >> 57);
    z0 ^= h0 ^ (h0 << 1) ^ (h0 << 2) ^ (h0 << 7);
    z1 ^= h1 ^ (h1 << 1) ^ (h1 << 2) ^ (h1 << 7) ^
          (h0 >> 63) ^ (h0 >> 62) ^ (h0 >> 57);
    z0 ^= q ^ (q << 1) ^ (q << 2) ^ (q << 7);
    sc_store_be64(x, reverse64(z0));
    sc_store_be64(x + 8, reverse64(z1));
    return 1;
}

#else
int sc_x86_ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    (void)x;
    (void)h;
    return 0;
}
#endif
