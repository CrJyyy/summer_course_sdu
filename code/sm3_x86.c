#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/*  CPU 特性检测（AVX2 / AVX512F / AVX512BW）                           */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/*  CPU 特性检测（修复了 Subleaf 0 查询 bug）                          */
/* ------------------------------------------------------------------ */
#if defined(_MSC_VER)
#include <intrin.h>
static inline void run_cpuid(int out[4], int eax) {
    __cpuid(out, eax);
}
static inline void run_cpuid_count(int out[4], int eax, int ecx) {
    __cpuidex(out, eax, ecx);
}
#else
#include <cpuid.h>
static inline void run_cpuid(int out[4], int eax) {
    __cpuid(eax, out[0], out[1], out[2], out[3]);
}
static inline void run_cpuid_count(int out[4], int eax, int ecx) {
    __cpuid_count(eax, ecx, out[0], out[1], out[2], out[3]);
}
#endif

static inline unsigned long long read_xcr0(void) {
#if defined(_MSC_VER)
    return _xgetbv(0);
#else
    unsigned int eax, edx;
    __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
    return ((unsigned long long)edx << 32) | eax;
#endif
}

static int cpu_has_avx2(void) {
    int info[4];
    run_cpuid(info, 1);
    if (!(info[2] & (1 << 28))) return 0;
    if (!(info[2] & (1 << 27))) return 0;
    if ((read_xcr0() & 0x06) != 0x06) return 0;
    run_cpuid_count(info, 7, 0); // 必须将 ECX 清零，正确查询 Subleaf 0
    return (info[1] & (1 << 5)) != 0;
}

static int cpu_has_avx512_bw(void) {
    int info[4];
    run_cpuid(info, 1);
    if (!(info[2] & (1 << 28))) return 0;
    if (!(info[2] & (1 << 27))) return 0;
    unsigned long long xcr0 = read_xcr0();
    if ((xcr0 & 0xE6) != 0xE6) return 0;
    run_cpuid_count(info, 7, 0); // 必须将 ECX 清零，正确查询 Subleaf 0
    if (!(info[1] & (1 << 16))) return 0; // AVX512F
    return (info[1] & (1 << 30)) != 0;    // AVX512BW
}

/* ------------------------------------------------------------------ */
/*  基础宏与类型定义                                                   */
/* ------------------------------------------------------------------ */
#define ROTL32(x, n) (((x) << ((n) & 31)) | ((x) >> ((32 - ((n) & 31)) & 31)))
#define P0(X) ((X) ^ ROTL32((X), 9) ^ ROTL32((X), 17))
#define P1(X) ((X) ^ ROTL32((X), 15) ^ ROTL32((X), 23))

#define FF0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FF1(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GG0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GG1(X, Y, Z) (((X) & (Y)) | (~(X) & (Z)))

typedef struct {
    uint32_t state[8];
    uint8_t  buffer[64];
    uint64_t total_bits;
} SM3_CTX;

void sm3_init(SM3_CTX *ctx) {
    ctx->state[0] = 0x7380166FU; ctx->state[1] = 0x4914B2B9U;
    ctx->state[2] = 0x172442D7U; ctx->state[3] = 0xDA8A0600U;
    ctx->state[4] = 0xA96F30BCU; ctx->state[5] = 0x163138AAU;
    ctx->state[6] = 0xE38DEE4DU; ctx->state[7] = 0xB0FB0E4EU;
    ctx->total_bits = 0;
}

/* ------------------------------------------------------------------ */
/*  64 轮压缩宏（正确顺序更新，无参数交换）                            */
/* ------------------------------------------------------------------ */
#define SM3_ROUND(j, TJ, FF, GG) do { \
    uint32_t _ss1 = ROTL32(ROTL32(A, 12) + E + ROTL32((uint32_t)(TJ), (j)), 7); \
    uint32_t _ss2 = _ss1 ^ ROTL32(A, 12); \
    uint32_t _tt1 = FF(A, B, C) + D + _ss2 + Wp[j]; \
    uint32_t _tt2 = GG(E, F, G) + H + _ss1 + W[j]; \
    D = C; \
    C = ROTL32(B, 9); \
    B = A; \
    A = _tt1; \
    H = G; \
    G = ROTL32(F, 19); \
    F = E; \
    E = P0(_tt2); \
} while(0)

/* ------------------------------------------------------------------ */
/*  标量回退版本                                                       */
/* ------------------------------------------------------------------ */
static void sm3_compress_scalar(uint32_t state[8], const uint8_t block[64])
{
    uint32_t W[68];
    uint32_t Wp[64];
    int j;

    for (j = 0; j < 16; j++) {
        W[j] = ((uint32_t)block[j * 4] << 24) | ((uint32_t)block[j * 4 + 1] << 16) |
               ((uint32_t)block[j * 4 + 2] << 8) | ((uint32_t)block[j * 4 + 3]);
    }
    for (j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^
               ROTL32(W[j - 13], 7) ^ W[j - 6];
    }
    for (j = 0; j < 64; j++) Wp[j] = W[j] ^ W[j + 4];

    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    SM3_ROUND( 0, 0x79CC4519U, FF0, GG0); SM3_ROUND( 1, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 2, 0x79CC4519U, FF0, GG0); SM3_ROUND( 3, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 4, 0x79CC4519U, FF0, GG0); SM3_ROUND( 5, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 6, 0x79CC4519U, FF0, GG0); SM3_ROUND( 7, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 8, 0x79CC4519U, FF0, GG0); SM3_ROUND( 9, 0x79CC4519U, FF0, GG0);
    SM3_ROUND(10, 0x79CC4519U, FF0, GG0); SM3_ROUND(11, 0x79CC4519U, FF0, GG0);
    SM3_ROUND(12, 0x79CC4519U, FF0, GG0); SM3_ROUND(13, 0x79CC4519U, FF0, GG0);
    SM3_ROUND(14, 0x79CC4519U, FF0, GG0); SM3_ROUND(15, 0x79CC4519U, FF0, GG0);

    SM3_ROUND(16, 0x7A879D8AU, FF1, GG1); SM3_ROUND(17, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(18, 0x7A879D8AU, FF1, GG1); SM3_ROUND(19, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(20, 0x7A879D8AU, FF1, GG1); SM3_ROUND(21, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(22, 0x7A879D8AU, FF1, GG1); SM3_ROUND(23, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(24, 0x7A879D8AU, FF1, GG1); SM3_ROUND(25, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(26, 0x7A879D8AU, FF1, GG1); SM3_ROUND(27, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(28, 0x7A879D8AU, FF1, GG1); SM3_ROUND(29, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(30, 0x7A879D8AU, FF1, GG1); SM3_ROUND(31, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(32, 0x7A879D8AU, FF1, GG1); SM3_ROUND(33, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(34, 0x7A879D8AU, FF1, GG1); SM3_ROUND(35, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(36, 0x7A879D8AU, FF1, GG1); SM3_ROUND(37, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(38, 0x7A879D8AU, FF1, GG1); SM3_ROUND(39, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(40, 0x7A879D8AU, FF1, GG1); SM3_ROUND(41, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(42, 0x7A879D8AU, FF1, GG1); SM3_ROUND(43, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(44, 0x7A879D8AU, FF1, GG1); SM3_ROUND(45, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(46, 0x7A879D8AU, FF1, GG1); SM3_ROUND(47, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(48, 0x7A879D8AU, FF1, GG1); SM3_ROUND(49, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(50, 0x7A879D8AU, FF1, GG1); SM3_ROUND(51, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(52, 0x7A879D8AU, FF1, GG1); SM3_ROUND(53, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(54, 0x7A879D8AU, FF1, GG1); SM3_ROUND(55, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(56, 0x7A879D8AU, FF1, GG1); SM3_ROUND(57, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(58, 0x7A879D8AU, FF1, GG1); SM3_ROUND(59, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(60, 0x7A879D8AU, FF1, GG1); SM3_ROUND(61, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(62, 0x7A879D8AU, FF1, GG1); SM3_ROUND(63, 0x7A879D8AU, FF1, GG1);

    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

/* ------------------------------------------------------------------ */
/*  AVX2 版本：256-bit SIMD + GPR 混合                                 */
/* ------------------------------------------------------------------ */
#if defined(__AVX2__) || defined(__AVX__) || defined(_MSC_VER)
#include <immintrin.h>

/* 32 字节对齐的 shuffle mask，避免编译器对 _mm256_setr_epi8 的支持差异 */
static const uint8_t SM3_SHUF_AVX2[32] __attribute__((aligned(32))) = {
    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
};

static void sm3_compress_avx2(uint32_t state[8], const uint8_t block[64])
{
    __attribute__((aligned(32))) uint32_t W[72];
    __attribute__((aligned(32))) uint32_t Wp[64];

    /* 1. AVX2 宽位加载 + 大端转小端 */
    __m256i shuf = _mm256_load_si256((const __m256i *)SM3_SHUF_AVX2);
    __m256i v0 = _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)block), shuf);
    __m256i v1 = _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)(block + 32)), shuf);
    _mm256_store_si256((__m256i *)&W[0], v0);
    _mm256_store_si256((__m256i *)&W[8], v1);

    /* 2. 标量递推 W[16..67] */
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^
               ROTL32(W[j - 13], 7) ^ W[j - 6];
    }

    /* 3. AVX2 向量化 W′ */
    for (int j = 0; j < 64; j += 8) {
        __m256i a = _mm256_loadu_si256((const __m256i *)&W[j]);
        __m256i b = _mm256_loadu_si256((const __m256i *)&W[j + 4]);
        _mm256_storeu_si256((__m256i *)&Wp[j], _mm256_xor_si256(a, b));
    }

    /* 4. GPR 64 轮全展开压缩 */
    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    SM3_ROUND( 0, 0x79CC4519U, FF0, GG0); SM3_ROUND( 1, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 2, 0x79CC4519U, FF0, GG0); SM3_ROUND( 3, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 4, 0x79CC4519U, FF0, GG0); SM3_ROUND( 5, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 6, 0x79CC4519U, FF0, GG0); SM3_ROUND( 7, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 8, 0x79CC4519U, FF0, GG0); SM3_ROUND( 9, 0x79CC4519U, FF0, GG0);
    SM3_ROUND(10, 0x79CC4519U, FF0, GG0); SM3_ROUND(11, 0x79CC4519U, FF0, GG0);
    SM3_ROUND(12, 0x79CC4519U, FF0, GG0); SM3_ROUND(13, 0x79CC4519U, FF0, GG0);
    SM3_ROUND(14, 0x79CC4519U, FF0, GG0); SM3_ROUND(15, 0x79CC4519U, FF0, GG0);

    SM3_ROUND(16, 0x7A879D8AU, FF1, GG1); SM3_ROUND(17, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(18, 0x7A879D8AU, FF1, GG1); SM3_ROUND(19, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(20, 0x7A879D8AU, FF1, GG1); SM3_ROUND(21, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(22, 0x7A879D8AU, FF1, GG1); SM3_ROUND(23, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(24, 0x7A879D8AU, FF1, GG1); SM3_ROUND(25, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(26, 0x7A879D8AU, FF1, GG1); SM3_ROUND(27, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(28, 0x7A879D8AU, FF1, GG1); SM3_ROUND(29, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(30, 0x7A879D8AU, FF1, GG1); SM3_ROUND(31, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(32, 0x7A879D8AU, FF1, GG1); SM3_ROUND(33, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(34, 0x7A879D8AU, FF1, GG1); SM3_ROUND(35, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(36, 0x7A879D8AU, FF1, GG1); SM3_ROUND(37, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(38, 0x7A879D8AU, FF1, GG1); SM3_ROUND(39, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(40, 0x7A879D8AU, FF1, GG1); SM3_ROUND(41, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(42, 0x7A879D8AU, FF1, GG1); SM3_ROUND(43, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(44, 0x7A879D8AU, FF1, GG1); SM3_ROUND(45, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(46, 0x7A879D8AU, FF1, GG1); SM3_ROUND(47, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(48, 0x7A879D8AU, FF1, GG1); SM3_ROUND(49, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(50, 0x7A879D8AU, FF1, GG1); SM3_ROUND(51, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(52, 0x7A879D8AU, FF1, GG1); SM3_ROUND(53, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(54, 0x7A879D8AU, FF1, GG1); SM3_ROUND(55, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(56, 0x7A879D8AU, FF1, GG1); SM3_ROUND(57, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(58, 0x7A879D8AU, FF1, GG1); SM3_ROUND(59, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(60, 0x7A879D8AU, FF1, GG1); SM3_ROUND(61, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(62, 0x7A879D8AU, FF1, GG1); SM3_ROUND(63, 0x7A879D8AU, FF1, GG1);

    /* 5. AVX2 宽位状态异或 */
    __m256i s = _mm256_loadu_si256((const __m256i *)state);
    __m256i n = _mm256_set_epi32((int)H,(int)G,(int)F,(int)E,(int)D,(int)C,(int)B,(int)A);
    _mm256_storeu_si256((__m256i *)state, _mm256_xor_si256(s, n));
}
#endif

/* ------------------------------------------------------------------ */
/*  AVX512 版本：512-bit SIMD + GPR 混合                               */
/* ------------------------------------------------------------------ */
#if defined(__AVX512F__) && defined(__AVX512BW__)
#include <immintrin.h>

/* 64 字节对齐的 shuffle mask，兼容所有 GCC/Clang/MSVC */
static const uint8_t SM3_SHUF_AVX512[64] __attribute__((aligned(64))) = {
    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
};

static void sm3_compress_avx512(uint32_t state[8], const uint8_t block[64])
{
    __attribute__((aligned(64))) uint32_t W[80];
    __attribute__((aligned(64))) uint32_t Wp[64];

    /* 1. AVX512BW 一次加载 64 字节并大端转小端 */
    __m512i shuf = _mm512_load_si512((const __m512i *)SM3_SHUF_AVX512);
    __m512i v = _mm512_shuffle_epi8(_mm512_loadu_si512((const __m512i *)block), shuf);
    _mm512_store_si512((__m512i *)&W[0], v);

    /* 2. 标量递推 W[16..67] */
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^
               ROTL32(W[j - 13], 7) ^ W[j - 6];
    }

    /* 3. AVX512 向量化 W′ */
    for (int j = 0; j < 64; j += 16) {
        __m512i a = _mm512_loadu_si512((const __m512i *)&W[j]);
        __m512i b = _mm512_loadu_si512((const __m512i *)&W[j + 4]);
        _mm512_storeu_si512((__m512i *)&Wp[j], _mm512_xor_si512(a, b));
    }

    /* 4. GPR 64 轮全展开压缩 */
    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    SM3_ROUND( 0, 0x79CC4519U, FF0, GG0); SM3_ROUND( 1, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 2, 0x79CC4519U, FF0, GG0); SM3_ROUND( 3, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 4, 0x79CC4519U, FF0, GG0); SM3_ROUND( 5, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 6, 0x79CC4519U, FF0, GG0); SM3_ROUND( 7, 0x79CC4519U, FF0, GG0);
    SM3_ROUND( 8, 0x79CC4519U, FF0, GG0); SM3_ROUND( 9, 0x79CC4519U, FF0, GG0);
    SM3_ROUND(10, 0x79CC4519U, FF0, GG0); SM3_ROUND(11, 0x79CC4519U, FF0, GG0);
    SM3_ROUND(12, 0x79CC4519U, FF0, GG0); SM3_ROUND(13, 0x79CC4519U, FF0, GG0);
    SM3_ROUND(14, 0x79CC4519U, FF0, GG0); SM3_ROUND(15, 0x79CC4519U, FF0, GG0);

    SM3_ROUND(16, 0x7A879D8AU, FF1, GG1); SM3_ROUND(17, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(18, 0x7A879D8AU, FF1, GG1); SM3_ROUND(19, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(20, 0x7A879D8AU, FF1, GG1); SM3_ROUND(21, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(22, 0x7A879D8AU, FF1, GG1); SM3_ROUND(23, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(24, 0x7A879D8AU, FF1, GG1); SM3_ROUND(25, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(26, 0x7A879D8AU, FF1, GG1); SM3_ROUND(27, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(28, 0x7A879D8AU, FF1, GG1); SM3_ROUND(29, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(30, 0x7A879D8AU, FF1, GG1); SM3_ROUND(31, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(32, 0x7A879D8AU, FF1, GG1); SM3_ROUND(33, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(34, 0x7A879D8AU, FF1, GG1); SM3_ROUND(35, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(36, 0x7A879D8AU, FF1, GG1); SM3_ROUND(37, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(38, 0x7A879D8AU, FF1, GG1); SM3_ROUND(39, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(40, 0x7A879D8AU, FF1, GG1); SM3_ROUND(41, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(42, 0x7A879D8AU, FF1, GG1); SM3_ROUND(43, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(44, 0x7A879D8AU, FF1, GG1); SM3_ROUND(45, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(46, 0x7A879D8AU, FF1, GG1); SM3_ROUND(47, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(48, 0x7A879D8AU, FF1, GG1); SM3_ROUND(49, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(50, 0x7A879D8AU, FF1, GG1); SM3_ROUND(51, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(52, 0x7A879D8AU, FF1, GG1); SM3_ROUND(53, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(54, 0x7A879D8AU, FF1, GG1); SM3_ROUND(55, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(56, 0x7A879D8AU, FF1, GG1); SM3_ROUND(57, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(58, 0x7A879D8AU, FF1, GG1); SM3_ROUND(59, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(60, 0x7A879D8AU, FF1, GG1); SM3_ROUND(61, 0x7A879D8AU, FF1, GG1);
    SM3_ROUND(62, 0x7A879D8AU, FF1, GG1); SM3_ROUND(63, 0x7A879D8AU, FF1, GG1);

    /* 5. AVX2/AVX512 宽位状态异或 */
    __m256i s = _mm256_loadu_si256((const __m256i *)state);
    __m256i n = _mm256_set_epi32((int)H,(int)G,(int)F,(int)E,(int)D,(int)C,(int)B,(int)A);
    _mm256_storeu_si256((__m256i *)state, _mm256_xor_si256(s, n));
}
#endif

#undef SM3_ROUND

/* ------------------------------------------------------------------ */
/*  运行时分发封装                                                     */
/* ------------------------------------------------------------------ */
static void (*g_compress_fn)(uint32_t state[8], const uint8_t block[64]) = NULL;

static void sm3_compress_dispatch(uint32_t state[8], const uint8_t block[64])
{
#if (defined(__AVX512F__) && defined(__AVX512BW__)) || defined(_MSC_VER)
    if (cpu_has_avx512_bw()) {
        g_compress_fn = sm3_compress_avx512;
        printf("[Dispatch] Using AVX512BW path\n");
    } else
#endif
#if defined(__AVX2__) || defined(__AVX__) || defined(_MSC_VER)
    if (cpu_has_avx2()) {
        g_compress_fn = sm3_compress_avx2;
        printf("[Dispatch] Using AVX2 path\n");
    } else
#endif
    {
        g_compress_fn = sm3_compress_scalar;
        printf("[Dispatch] Using Scalar path\n");
    }
    g_compress_fn(state, block);
}

static inline void sm3_compress(uint32_t state[8], const uint8_t block[64])
{
    if (g_compress_fn)
        g_compress_fn(state, block);
    else
        sm3_compress_dispatch(state, block);
}

/* ------------------------------------------------------------------ */
/*  标准的 update / final                                              */
/* ------------------------------------------------------------------ */
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t len)
{
    size_t offset = (ctx->total_bits / 8) % 64;
    ctx->total_bits += (uint64_t)len * 8;

    while (len > 0) {
        size_t space = 64 - offset;
        size_t chunk = (len < space) ? len : space;
        memcpy(ctx->buffer + offset, data, chunk);
        data += chunk; len -= chunk; offset += chunk;

        if (offset == 64) {
            sm3_compress(ctx->state, ctx->buffer);
            offset = 0;
        }
    }
}

void sm3_final(SM3_CTX *ctx, uint8_t digest[32])
{
    uint64_t total_bits = ctx->total_bits;
    size_t offset = (total_bits / 8) % 64;

    ctx->buffer[offset++] = 0x80;
    if (offset > 56) {
        memset(ctx->buffer + offset, 0, 64 - offset);
        sm3_compress(ctx->state, ctx->buffer);
        offset = 0;
    }
    memset(ctx->buffer + offset, 0, 56 - offset);

    ctx->buffer[56] = (uint8_t)(total_bits >> 56); ctx->buffer[57] = (uint8_t)(total_bits >> 48);
    ctx->buffer[58] = (uint8_t)(total_bits >> 40); ctx->buffer[59] = (uint8_t)(total_bits >> 32);
    ctx->buffer[60] = (uint8_t)(total_bits >> 24); ctx->buffer[61] = (uint8_t)(total_bits >> 16);
    ctx->buffer[62] = (uint8_t)(total_bits >> 8);  ctx->buffer[63] = (uint8_t)(total_bits);

    sm3_compress(ctx->state, ctx->buffer);

    for (int i = 0; i < 8; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/* ------------------------------------------------------------------ */
/*  测试主函数                                                         */
/* ------------------------------------------------------------------ */
int main(void)
{
    printf("=== SM3 AVX2/AVX512 Hybrid Optimization (Fixed) ===\n");

    SM3_CTX ctx;
    uint8_t hash[32];
    const char *msg = "abc";
    sm3_init(&ctx);
    sm3_update(&ctx, (const uint8_t *)msg, strlen(msg));
    sm3_final(&ctx, hash);
    printf("Verify 'abc' Hash: ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");

    const size_t test_size = 10 * 1024 * 1024;
    const int iterations = 10;
    uint8_t *large_data = (uint8_t *)malloc(test_size);
    if (!large_data) return -1;
    memset(large_data, 0x5A, test_size);

    sm3_init(&ctx);
    sm3_update(&ctx, large_data, 64);
    sm3_final(&ctx, hash);

    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        sm3_init(&ctx);
        sm3_update(&ctx, large_data, test_size);
        sm3_final(&ctx, hash);
    }
    clock_t end = clock();

    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    double total_mb = (double)(test_size * iterations) / (1024 * 1024);
    printf("Processed: %.1f MB\n", total_mb);
    printf("Time elapsed: %.3f seconds\n", seconds);
    printf("Throughput: %.2f MB/s\n", total_mb / seconds);

    free(large_data);
    return 0;
}
