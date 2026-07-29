#define _CRT_SECURE_NO_WARNINGS
#include <stdalign.h> 
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arm_neon.h> // ARM64 NEON 向量寄存器头文件

// 32 位循环左移
static inline uint32_t ROTL32(uint32_t x, int n) {
    unsigned int mask = (unsigned int)n & 31U;
    return (x << mask) | (x >> ((32U - mask) & 31U));
}

#define P0(X) ((X) ^ ROTL32((X), 9) ^ ROTL32((X), 17))
#define P1(X) ((X) ^ ROTL32((X), 15) ^ ROTL32((X), 23))

#define FF0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FF1(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GG0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GG1(X, Y, Z) (((X) & (Y)) | (~(X) & (Z)))

typedef struct {
    uint32_t state[8];
    uint8_t buffer[64];
    uint64_t total_bits;
} SM3_CTX;

void sm3_init(SM3_CTX *ctx) {
    ctx->state[0] = 0x7380166FU; ctx->state[1] = 0x4914B2B9U;
    ctx->state[2] = 0x172442D7U; ctx->state[3] = 0xDA8A0600U;
    ctx->state[4] = 0xA96F30BCU; ctx->state[5] = 0x163138AAU;
    ctx->state[6] = 0xE38DEE4DU; ctx->state[7] = 0xB0FB0E4EU;
    ctx->total_bits = 0;
}

void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    // 16 字局部滑动窗口，完全展开后编译器可直接将其提升至 ARM64 GPR 通用寄存器中
    alignas(16) uint32_t r[16];

    // NEON 快速向量加载与大小端（字节逆序）转换
    uint32x4_t w0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block)));
    uint32x4_t w1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
    uint32x4_t w2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
    uint32x4_t w3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

    vst1q_u32(&r[0], w0);
    vst1q_u32(&r[4], w1);
    vst1q_u32(&r[8], w2);
    vst1q_u32(&r[12], w3);

    // 状态变量初始化
    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    // 在线消息扩展与迭代压缩交错执行（On-the-fly），大幅消除对栈内存的连续读写
    #define ROUND_ON_THE_FLY(A, B, C, D, E, F, G, H, TJ, FF, GG, j) \
        do { \
            uint32_t wj = r[(j) % 16]; \
            if ((j) >= 12) { \
                r[((j) + 4) % 16] = P1(r[((j) + 4) % 16] ^ r[((j) + 11) % 16] ^ ROTL32(r[((j) + 1) % 16], 15)) ^ ROTL32(r[((j) + 7) % 16], 7) ^ r[((j) + 14) % 16]; \
            } \
            uint32_t wj_prime = wj ^ r[((j) + 4) % 16]; \
            uint32_t ss1 = ROTL32(ROTL32(A, 12) + E + (uint32_t)(TJ), 7); \
            uint32_t ss2 = ss1 ^ ROTL32(A, 12); \
            uint32_t tt1 = FF(A, B, C) + D + ss2 + wj_prime; \
            uint32_t tt2 = GG(E, F, G) + H + ss1 + wj; \
            D = tt1; \
            B = ROTL32(B, 9); \
            H = P0(tt2); \
            F = ROTL32(F, 19); \
        } while(0)

    #define ROUND_0_15(A, B, C, D, E, F, G, H, j) \
        ROUND_ON_THE_FLY(A, B, C, D, E, F, G, H, ROTL32(0x79CC4519U, (j)), FF0, GG0, j)

    #define ROUND_16_63(A, B, C, D, E, F, G, H, j) \
        ROUND_ON_THE_FLY(A, B, C, D, E, F, G, H, ROTL32(0x7A879D8AU, (j) % 32), FF1, GG1, j)

    // 64 轮迭代全展开
    ROUND_0_15(A, B, C, D, E, F, G, H, 0);
    ROUND_0_15(D, A, B, C, H, E, F, G, 1);
    ROUND_0_15(C, D, A, B, G, H, E, F, 2);
    ROUND_0_15(B, C, D, A, F, G, H, E, 3);
    ROUND_0_15(A, B, C, D, E, F, G, H, 4);
    ROUND_0_15(D, A, B, C, H, E, F, G, 5);
    ROUND_0_15(C, D, A, B, G, H, E, F, 6);
    ROUND_0_15(B, C, D, A, F, G, H, E, 7);
    ROUND_0_15(A, B, C, D, E, F, G, H, 8);
    ROUND_0_15(D, A, B, C, H, E, F, G, 9);
    ROUND_0_15(C, D, A, B, G, H, E, F, 10);
    ROUND_0_15(B, C, D, A, F, G, H, E, 11);
    ROUND_0_15(A, B, C, D, E, F, G, H, 12);
    ROUND_0_15(D, A, B, C, H, E, F, G, 13);
    ROUND_0_15(C, D, A, B, G, H, E, F, 14);
    ROUND_0_15(B, C, D, A, F, G, H, E, 15);

    ROUND_16_63(A, B, C, D, E, F, G, H, 16);
    ROUND_16_63(D, A, B, C, H, E, F, G, 17);
    ROUND_16_63(C, D, A, B, G, H, E, F, 18);
    ROUND_16_63(B, C, D, A, F, G, H, E, 19);
    ROUND_16_63(A, B, C, D, E, F, G, H, 20);
    ROUND_16_63(D, A, B, C, H, E, F, G, 21);
    ROUND_16_63(C, D, A, B, G, H, E, F, 22);
    ROUND_16_63(B, C, D, A, F, G, H, E, 23);
    ROUND_16_63(A, B, C, D, E, F, G, H, 24);
    ROUND_16_63(D, A, B, C, H, E, F, G, 25);
    ROUND_16_63(C, D, A, B, G, H, E, F, 26);
    ROUND_16_63(B, C, D, A, F, G, H, E, 27);
    ROUND_16_63(A, B, C, D, E, F, G, H, 28);
    ROUND_16_63(D, A, B, C, H, E, F, G, 29);
    ROUND_16_63(C, D, A, B, G, H, E, F, 30);
    ROUND_16_63(B, C, D, A, F, G, H, E, 31);
    ROUND_16_63(A, B, C, D, E, F, G, H, 32);
    ROUND_16_63(D, A, B, C, H, E, F, G, 33);
    ROUND_16_63(C, D, A, B, G, H, E, F, 34);
    ROUND_16_63(B, C, D, A, F, G, H, E, 35);
    ROUND_16_63(A, B, C, D, E, F, G, H, 36);
    ROUND_16_63(D, A, B, C, H, E, F, G, 37);
    ROUND_16_63(C, D, A, B, G, H, E, F, 38);
    ROUND_16_63(B, C, D, A, F, G, H, E, 39);
    ROUND_16_63(A, B, C, D, E, F, G, H, 40);
    ROUND_16_63(D, A, B, C, H, E, F, G, 41);
    ROUND_16_63(C, D, A, B, G, H, E, F, 42);
    ROUND_16_63(B, C, D, A, F, G, H, E, 43);
    ROUND_16_63(A, B, C, D, E, F, G, H, 44);
    ROUND_16_63(D, A, B, C, H, E, F, G, 45);
    ROUND_16_63(C, D, A, B, G, H, E, F, 46);
    ROUND_16_63(B, C, D, A, F, G, H, E, 47);
    ROUND_16_63(A, B, C, D, E, F, G, H, 48);
    ROUND_16_63(D, A, B, C, H, E, F, G, 49);
    ROUND_16_63(C, D, A, B, G, H, E, F, 50);
    ROUND_16_63(B, C, D, A, F, G, H, E, 51);
    ROUND_16_63(A, B, C, D, E, F, G, H, 52);
    ROUND_16_63(D, A, B, C, H, E, F, G, 53);
    ROUND_16_63(C, D, A, B, G, H, E, F, 54);
    ROUND_16_63(B, C, D, A, F, G, H, E, 55);
    ROUND_16_63(A, B, C, D, E, F, G, H, 56);
    ROUND_16_63(D, A, B, C, H, E, F, G, 57);
    ROUND_16_63(C, D, A, B, G, H, E, F, 58);
    ROUND_16_63(B, C, D, A, F, G, H, E, 59);
    ROUND_16_63(A, B, C, D, E, F, G, H, 60);
    ROUND_16_63(D, A, B, C, H, E, F, G, 61);
    ROUND_16_63(C, D, A, B, G, H, E, F, 62);
    ROUND_16_63(B, C, D, A, F, G, H, E, 63);

    #undef ROUND_ON_THE_FLY
    #undef ROUND_0_15
    #undef ROUND_16_63

    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t len) {
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

void sm3_final(SM3_CTX *ctx, uint8_t digest[32]) {
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

int main() {
    printf(" (ARM64 NEON + GPR Mixed) SM3\n");
    
    SM3_CTX ctx;
    uint8_t hash[32];
    const char *msg = "abc";
    sm3_init(&ctx);
    sm3_update(&ctx, (const uint8_t *)msg, strlen(msg));
    sm3_final(&ctx, hash);
    printf("Verify 'abc' Hash: ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");

    const size_t test_size = 10 * 1024 * 1024; // 10MB
    const int iterations = 10;                // 10次迭代，共100MB
    uint8_t *large_data = (uint8_t *)malloc(test_size);
    if (!large_data) return -1;
    memset(large_data, 0x5A, test_size);

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
    printf("Throughput: %.2f MB/s\n\n", total_mb / seconds);

    free(large_data);
    return 0;
}
