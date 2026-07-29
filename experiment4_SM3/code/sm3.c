#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ROTL32(x, n) (((x) << ((n) & 31)) | ((x) >> ((32 - ((n) & 31)) & 31)))
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
    ctx->state[0] = 0x7380166F; ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7; ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC; ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D; ctx->state[7] = 0xB0FB0E4E;
    ctx->total_bits = 0;
}

void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68];
    uint32_t W_prime[64];
    int j;

    for (j = 0; j < 16; j++) {
        W[j] = ((uint32_t)block[j * 4] << 24) | ((uint32_t)block[j * 4 + 1] << 16) |
               ((uint32_t)block[j * 4 + 2] << 8) | ((uint32_t)block[j * 4 + 3]);
    }

    for (j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
    }

    for (j = 0; j < 64; j++) {
        W_prime[j] = W[j] ^ W[j + 4];
    }

    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];
    uint32_t SS1, SS2, TT1, TT2, Tj;

    for (j = 0; j < 16; j++) {
        Tj = 0x79CC4519;
        SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(Tj, j), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF0(A, B, C) + D + SS2 + W_prime[j];
        TT2 = GG0(E, F, G) + H + SS1 + W[j];
        D = C; C = ROTL32(B, 9); B = A; A = TT1;
        H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);
    }

    for (j = 16; j < 64; j++) {
        Tj = 0x7A879D8A;
        SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(Tj, j), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF1(A, B, C) + D + SS2 + W_prime[j];
        TT2 = GG1(E, F, G) + H + SS1 + W[j];
        D = C; C = ROTL32(B, 9); B = A; A = TT1;
        H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);
    }

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
    printf("Baseline SM3\n");
    
    // 验证测试
    SM3_CTX ctx;
    uint8_t hash[32];
    const char *msg = "abc";
    sm3_init(&ctx);
    sm3_update(&ctx, (const uint8_t *)msg, strlen(msg));
    sm3_final(&ctx, hash);
    printf("Verify 'abc' Hash: ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");

    // 吞吐量测试: 处理 100 MB 数据
    const size_t test_size = 10 * 1024 * 1024; // 单次 10MB
    const int iterations = 10;                // 循环 10 次 (共计 100MB)
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
