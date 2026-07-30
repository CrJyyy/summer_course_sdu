#include "internal.h"

#include <stdatomic.h>

static uint8_t premap[16][16];
static atomic_flag premap_lock = ATOMIC_FLAG_INIT;
static atomic_int premap_ready;

static void init_premap(void) {
    if (atomic_load_explicit(&premap_ready, memory_order_acquire)) return;
    while (atomic_flag_test_and_set_explicit(&premap_lock, memory_order_acquire)) { }
    if (!atomic_load_explicit(&premap_ready, memory_order_relaxed)) {
        for (unsigned x = 0; x < 256; ++x)
            premap[x >> 4][x & 15] =
                sc_aes_inv_sbox_byte(sc_sm4_sbox_byte((uint8_t)x));
        atomic_store_explicit(&premap_ready, 1, memory_order_release);
    }
    atomic_flag_clear_explicit(&premap_lock, memory_order_release);
}

#if defined(__aarch64__) || defined(__arm64__)
#include <arm_neon.h>

static uint8x16_t map_before_aes(uint8x16_t x) {
    uint8x16_t lo = vandq_u8(x, vdupq_n_u8(15));
    uint8x16_t hi = vshrq_n_u8(x, 4);
    uint8x16_t y = vdupq_n_u8(0);
    for (uint8_t row = 0; row < 16; ++row) {
        uint8x16_t candidate = vqtbl1q_u8(vld1q_u8(premap[row]), lo);
        y = vorrq_u8(y, vandq_u8(candidate, vceqq_u8(hi, vdupq_n_u8(row))));
    }
    return y;
}

static uint32x4_t rotlq(uint32x4_t x, int n) {
    return vorrq_u32(vshlq_u32(x, vdupq_n_s32(n)),
                     vshlq_u32(x, vdupq_n_s32(n - 32)));
}

void sc_sm4_encrypt4_aes_assist(const sc_sm4_key *key, const uint8_t in[64],
                                uint8_t out[64]) {
    static const uint8_t inv_shift[16] =
        {0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3};
    init_premap();
    uint32_t words[4];
    uint32x4_t x[36];
    for (size_t w = 0; w < 4; ++w) {
        for (size_t lane = 0; lane < 4; ++lane)
            words[lane] = sc_load_be32(in + 16 * lane + 4 * w);
        x[w] = vld1q_u32(words);
    }
    uint8x16_t inverse_shift = vld1q_u8(inv_shift);
    for (size_t r = 0; r < 32; ++r) {
        uint32x4_t q = veorq_u32(
            veorq_u32(x[r + 1], x[r + 2]),
            veorq_u32(x[r + 3], vdupq_n_u32(key->rk[r])));
        uint8x16_t mapped = map_before_aes(vreinterpretq_u8_u32(q));
        uint32x4_t b = vreinterpretq_u32_u8(vqtbl1q_u8(
            vaeseq_u8(mapped, vdupq_n_u8(0)), inverse_shift));
        uint32x4_t l = veorq_u32(
            veorq_u32(b, rotlq(b, 2)),
            veorq_u32(rotlq(b, 10), veorq_u32(rotlq(b, 18), rotlq(b, 24))));
        x[r + 4] = veorq_u32(x[r], l);
    }
    for (size_t w = 0; w < 4; ++w) {
        vst1q_u32(words, x[35U - w]);
        for (size_t lane = 0; lane < 4; ++lane)
            sc_store_be32(out + 16 * lane + 4 * w, words[lane]);
    }
}

#elif defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>

__attribute__((target("aes,ssse3")))
void sc_sm4_encrypt4_aes_assist(const sc_sm4_key *key, const uint8_t in[64],
                                uint8_t out[64]) {
    static const uint8_t inv_shift[16] =
        {0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3};
    init_premap();
    uint32_t words[4];
    __m128i x[36];
    for (size_t w = 0; w < 4; ++w) {
        for (size_t lane = 0; lane < 4; ++lane)
            words[lane] = sc_load_be32(in + 16 * lane + 4 * w);
        x[w] = _mm_loadu_si128((const __m128i *)(const void *)words);
    }
    __m128i inverse_shift = _mm_loadu_si128(
        (const __m128i *)(const void *)inv_shift);
    for (size_t r = 0; r < 32; ++r) {
        __m128i q = _mm_xor_si128(
            _mm_xor_si128(x[r + 1], x[r + 2]),
            _mm_xor_si128(x[r + 3], _mm_set1_epi32((int)key->rk[r])));
        __m128i lo = _mm_and_si128(q, _mm_set1_epi8(15));
        __m128i hi = _mm_and_si128(_mm_srli_epi16(q, 4), _mm_set1_epi8(15));
        __m128i mapped = _mm_setzero_si128();
        for (int row = 0; row < 16; ++row) {
            __m128i table = _mm_loadu_si128(
                (const __m128i *)(const void *)premap[row]);
            __m128i candidate = _mm_shuffle_epi8(table, lo);
            mapped = _mm_or_si128(mapped, _mm_and_si128(
                candidate, _mm_cmpeq_epi8(hi, _mm_set1_epi8((char)row))));
        }
        __m128i b = _mm_shuffle_epi8(
            _mm_aesenclast_si128(mapped, _mm_setzero_si128()), inverse_shift);
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
void sc_sm4_encrypt4_aes_assist(const sc_sm4_key *key, const uint8_t in[64],
                                uint8_t out[64]) {
    for (size_t i = 0; i < 4; ++i)
        sc_sm4_encrypt_ref(key, in + 16 * i, out + 16 * i);
}
#endif
