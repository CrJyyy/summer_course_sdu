#include "../internal.h"

#if defined(__aarch64__) || defined(__arm64__)
#include <arm_neon.h>

int sc_arm_aes_available(void) {
    return sc_detect_cpu_features().arm_aes;
}

void sc_arm_aes_encrypt(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]) {
    uint8x16_t s = vld1q_u8(in);
    for (int r = 0; r < key->rounds - 1; ++r) {
        s = vaeseq_u8(s, vld1q_u8(key->round_key + 16 * r));
        s = vaesmcq_u8(s);
    }
    s = vaeseq_u8(s, vld1q_u8(key->round_key + 16 * (key->rounds - 1)));
    s = veorq_u8(s, vld1q_u8(key->round_key + 16 * key->rounds));
    vst1q_u8(out, s);
}

void sc_arm_aes_decrypt(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]) {
    uint8x16_t s = vld1q_u8(in);
    s = vaesimcq_u8(vaesdq_u8(
        s, vld1q_u8(key->round_key + 16 * key->rounds)));
    for (int r = key->rounds - 1; r > 1; --r)
        s = vaesimcq_u8(vaesdq_u8(
            s, vaesimcq_u8(vld1q_u8(key->round_key + 16 * r))));
    s = vaesdq_u8(s, vaesimcq_u8(vld1q_u8(key->round_key + 16)));
    s = veorq_u8(s, vld1q_u8(key->round_key));
    vst1q_u8(out, s);
}

void sc_arm_aes_encrypt4(const sc_aes_key *key, const uint8_t in[64],
                         uint8_t out[64]) {
    uint8x16_t s[4];
    for (size_t i = 0; i < 4; ++i) s[i] = vld1q_u8(in + 16 * i);
    for (int r = 0; r < key->rounds - 1; ++r) {
        uint8x16_t rk = vld1q_u8(key->round_key + 16 * r);
        for (size_t i = 0; i < 4; ++i) s[i] = vaesmcq_u8(vaeseq_u8(s[i], rk));
    }
    uint8x16_t rk = vld1q_u8(key->round_key + 16 * (key->rounds - 1));
    uint8x16_t last = vld1q_u8(key->round_key + 16 * key->rounds);
    for (size_t i = 0; i < 4; ++i)
        vst1q_u8(out + 16 * i, veorq_u8(vaeseq_u8(s[i], rk), last));
}

void sc_arm_aes_decrypt4(const sc_aes_key *key, const uint8_t in[64],
                         uint8_t out[64]) {
    uint8x16_t s[4];
    for (size_t i = 0; i < 4; ++i) s[i] = vld1q_u8(in + 16 * i);
    uint8x16_t rk = vld1q_u8(key->round_key + 16 * key->rounds);
    for (size_t i = 0; i < 4; ++i)
        s[i] = vaesimcq_u8(vaesdq_u8(s[i], rk));
    for (int r = key->rounds - 1; r > 1; --r) {
        rk = vaesimcq_u8(vld1q_u8(key->round_key + 16 * r));
        for (size_t i = 0; i < 4; ++i)
            s[i] = vaesimcq_u8(vaesdq_u8(s[i], rk));
    }
    rk = vaesimcq_u8(vld1q_u8(key->round_key + 16));
    uint8x16_t last = vld1q_u8(key->round_key);
    for (size_t i = 0; i < 4; ++i)
        vst1q_u8(out + 16 * i, veorq_u8(vaesdq_u8(s[i], rk), last));
}

#elif defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>

int sc_arm_aes_available(void) {
    return sc_detect_cpu_features().x86_aesni;
}

__attribute__((target("aes")))
void sc_arm_aes_encrypt(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]) {
    __m128i s = _mm_loadu_si128((const __m128i *)(const void *)in);
    s = _mm_xor_si128(s, _mm_loadu_si128(
        (const __m128i *)(const void *)key->round_key));
    for (int r = 1; r < key->rounds; ++r)
        s = _mm_aesenc_si128(s, _mm_loadu_si128(
            (const __m128i *)(const void *)(key->round_key + 16 * r)));
    s = _mm_aesenclast_si128(s, _mm_loadu_si128(
        (const __m128i *)(const void *)(key->round_key + 16 * key->rounds)));
    _mm_storeu_si128((__m128i *)(void *)out, s);
}

__attribute__((target("aes")))
void sc_arm_aes_decrypt(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]) {
    __m128i s = _mm_loadu_si128((const __m128i *)(const void *)in);
    s = _mm_xor_si128(s, _mm_loadu_si128((const __m128i *)(const void *)
                                         (key->round_key + 16 * key->rounds)));
    for (int r = key->rounds - 1; r > 0; --r) {
        __m128i rk = _mm_aesimc_si128(_mm_loadu_si128(
            (const __m128i *)(const void *)(key->round_key + 16 * r)));
        s = _mm_aesdec_si128(s, rk);
    }
    s = _mm_aesdeclast_si128(s, _mm_loadu_si128(
        (const __m128i *)(const void *)key->round_key));
    _mm_storeu_si128((__m128i *)(void *)out, s);
}

__attribute__((target("aes")))
void sc_arm_aes_encrypt4(const sc_aes_key *key, const uint8_t in[64],
                         uint8_t out[64]) {
    __m128i s[4];
    __m128i rk = _mm_loadu_si128((const __m128i *)(const void *)key->round_key);
    for (size_t i = 0; i < 4; ++i)
        s[i] = _mm_xor_si128(_mm_loadu_si128(
            (const __m128i *)(const void *)(in + 16 * i)), rk);
    for (int r = 1; r < key->rounds; ++r) {
        rk = _mm_loadu_si128((const __m128i *)(const void *)
                             (key->round_key + 16 * r));
        for (size_t i = 0; i < 4; ++i) s[i] = _mm_aesenc_si128(s[i], rk);
    }
    rk = _mm_loadu_si128((const __m128i *)(const void *)
                         (key->round_key + 16 * key->rounds));
    for (size_t i = 0; i < 4; ++i)
        _mm_storeu_si128((__m128i *)(void *)(out + 16 * i),
                         _mm_aesenclast_si128(s[i], rk));
}

__attribute__((target("aes")))
void sc_arm_aes_decrypt4(const sc_aes_key *key, const uint8_t in[64],
                         uint8_t out[64]) {
    __m128i s[4];
    __m128i rk = _mm_loadu_si128((const __m128i *)(const void *)
                                 (key->round_key + 16 * key->rounds));
    for (size_t i = 0; i < 4; ++i)
        s[i] = _mm_xor_si128(_mm_loadu_si128(
            (const __m128i *)(const void *)(in + 16 * i)), rk);
    for (int r = key->rounds - 1; r > 0; --r) {
        rk = _mm_aesimc_si128(_mm_loadu_si128(
            (const __m128i *)(const void *)(key->round_key + 16 * r)));
        for (size_t i = 0; i < 4; ++i) s[i] = _mm_aesdec_si128(s[i], rk);
    }
    rk = _mm_loadu_si128((const __m128i *)(const void *)key->round_key);
    for (size_t i = 0; i < 4; ++i)
        _mm_storeu_si128((__m128i *)(void *)(out + 16 * i),
                         _mm_aesdeclast_si128(s[i], rk));
}

#else
int sc_arm_aes_available(void) {
    return 0;
}

void sc_arm_aes_encrypt(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]) {
    sc_aes_encrypt_ref(key, in, out);
}

void sc_arm_aes_decrypt(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]) {
    sc_aes_decrypt_ref(key, in, out);
}
void sc_arm_aes_encrypt4(const sc_aes_key *key, const uint8_t in[64],
                         uint8_t out[64]) {
    for (size_t i = 0; i < 4; ++i)
        sc_aes_encrypt_ref(key, in + 16 * i, out + 16 * i);
}
void sc_arm_aes_decrypt4(const sc_aes_key *key, const uint8_t in[64],
                         uint8_t out[64]) {
    for (size_t i = 0; i < 4; ++i)
        sc_aes_decrypt_ref(key, in + 16 * i, out + 16 * i);
}
#endif
