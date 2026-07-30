#include "../internal.h"

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>

__attribute__((target("aes,avx2,vaes")))
void sc_x86_aes_encrypt8_vaes(const sc_aes_key *key, const uint8_t in[128],
                               uint8_t out[128]) {
    __m256i s[4];
    __m128i k128 = _mm_loadu_si128(
        (const __m128i *)(const void *)key->round_key);
    __m256i rk = _mm256_broadcastsi128_si256(k128);
    for (size_t i = 0; i < 4; ++i)
        s[i] = _mm256_xor_si256(_mm256_loadu_si256(
            (const __m256i *)(const void *)(in + 32 * i)), rk);
    for (int r = 1; r < key->rounds; ++r) {
        k128 = _mm_loadu_si128((const __m128i *)(const void *)
                               (key->round_key + 16 * r));
        rk = _mm256_broadcastsi128_si256(k128);
        for (size_t i = 0; i < 4; ++i) s[i] = _mm256_aesenc_epi128(s[i], rk);
    }
    k128 = _mm_loadu_si128((const __m128i *)(const void *)
                           (key->round_key + 16 * key->rounds));
    rk = _mm256_broadcastsi128_si256(k128);
    for (size_t i = 0; i < 4; ++i)
        _mm256_storeu_si256((__m256i *)(void *)(out + 32 * i),
                            _mm256_aesenclast_epi128(s[i], rk));
}

__attribute__((target("aes,avx2,vaes")))
void sc_x86_aes_decrypt8_vaes(const sc_aes_key *key, const uint8_t in[128],
                               uint8_t out[128]) {
    __m256i s[4];
    __m128i k128 = _mm_loadu_si128((const __m128i *)(const void *)
                                   (key->round_key + 16 * key->rounds));
    __m256i rk = _mm256_broadcastsi128_si256(k128);
    for (size_t i = 0; i < 4; ++i)
        s[i] = _mm256_xor_si256(_mm256_loadu_si256(
            (const __m256i *)(const void *)(in + 32 * i)), rk);
    for (int r = key->rounds - 1; r > 0; --r) {
        k128 = _mm_aesimc_si128(_mm_loadu_si128(
            (const __m128i *)(const void *)(key->round_key + 16 * r)));
        rk = _mm256_broadcastsi128_si256(k128);
        for (size_t i = 0; i < 4; ++i) s[i] = _mm256_aesdec_epi128(s[i], rk);
    }
    k128 = _mm_loadu_si128((const __m128i *)(const void *)key->round_key);
    rk = _mm256_broadcastsi128_si256(k128);
    for (size_t i = 0; i < 4; ++i)
        _mm256_storeu_si256((__m256i *)(void *)(out + 32 * i),
                            _mm256_aesdeclast_epi128(s[i], rk));
}

#else
void sc_x86_aes_encrypt8_vaes(const sc_aes_key *key, const uint8_t in[128],
                               uint8_t out[128]) {
    for (size_t i = 0; i < 8; ++i)
        sc_aes_encrypt_ref(key, in + 16 * i, out + 16 * i);
}
void sc_x86_aes_decrypt8_vaes(const sc_aes_key *key, const uint8_t in[128],
                               uint8_t out[128]) {
    for (size_t i = 0; i < 8; ++i)
        sc_aes_decrypt_ref(key, in + 16 * i, out + 16 * i);
}
#endif
