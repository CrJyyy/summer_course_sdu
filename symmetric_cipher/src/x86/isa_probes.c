#include <immintrin.h>

/*
 * Cross-compiled ISA witnesses.  They are not linked into the ARM executable;
 * scripts/check_x86.sh disassembles this object and checks every mnemonic.
 */
__attribute__((noinline))
__m128i sc_x86_probe_aesenc(__m128i a, __m128i b) {
    return _mm_aesenc_si128(a, b);
}

__attribute__((noinline))
__m256i sc_x86_probe_vaes(__m256i a, __m256i b) {
    return _mm256_aesenc_epi128(a, b);
}

__attribute__((noinline))
__m256i sc_x86_probe_pshufb(__m256i a, __m256i b) {
    return _mm256_shuffle_epi8(a, b);
}

__attribute__((noinline))
__m128i sc_x86_probe_pclmul(__m128i a, __m128i b) {
    return _mm_clmulepi64_si128(a, b, 0x00);
}

__attribute__((noinline))
__m256i sc_x86_probe_vpclmul(__m256i a, __m256i b) {
    return _mm256_clmulepi64_epi128(a, b, 0x00);
}

__attribute__((noinline))
__m128i sc_x86_probe_gfni(__m128i a, __m128i matrix) {
    return _mm_gf2p8affineinv_epi64_epi8(a, matrix, 0xd3);
}

__attribute__((noinline))
__m256i sc_x86_probe_sm4(__m256i a, __m256i b) {
    return _mm256_sm4rnds4_epi32(a, b);
}
