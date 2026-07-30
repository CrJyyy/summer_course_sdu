#include "../internal.h"

#if (defined(__aarch64__) || defined(__arm64__)) && defined(__ARM_FEATURE_SM4)
#include <arm_neon.h>

static const uint32_t fk[4] =
    {0xa3b1bac6U,0x56aa3350U,0x677d9197U,0xb27022dcU};
static const uint32_t ck[32] = {
 0x00070e15U,0x1c232a31U,0x383f464dU,0x545b6269U,
 0x70777e85U,0x8c939aa1U,0xa8afb6bdU,0xc4cbd2d9U,
 0xe0e7eef5U,0xfc030a11U,0x181f262dU,0x343b4249U,
 0x50575e65U,0x6c737a81U,0x888f969dU,0xa4abb2b9U,
 0xc0c7ced5U,0xdce3eaf1U,0xf8ff060dU,0x141b2229U,
 0x30373e45U,0x4c535a61U,0x686f767dU,0x848b9299U,
 0xa0a7aeb5U,0xbcc3cad1U,0xd8dfe6edU,0xf4fb0209U,
 0x10171e25U,0x2c333a41U,0x484f565dU,0x646b7279U
};

void sc_arm_sm4_setkey_hw(sc_sm4_key *key, const uint8_t raw[16]) {
    uint32_t words[4];
    for (size_t i = 0; i < 4; ++i) words[i] = sc_load_be32(raw + 4 * i) ^ fk[i];
    uint32x4_t state = vld1q_u32(words);
    for (size_t r = 0; r < 32; r += 4) {
        state = vsm4ekeyq_u32(state, vld1q_u32(ck + r));
        vst1q_u32(key->rk + r, state);
    }
}

static uint32x4_t load_state(const uint8_t in[16]) {
    uint32_t words[4];
    for (size_t i = 0; i < 4; ++i) words[i] = sc_load_be32(in + 4 * i);
    return vld1q_u32(words);
}

static void store_state(uint8_t out[16], uint32x4_t state) {
    uint32_t words[4];
    vst1q_u32(words, state);
    for (size_t i = 0; i < 4; ++i) sc_store_be32(out + 4 * i, words[3U - i]);
}

void sc_arm_sm4_encrypt4_hw(const sc_sm4_key *key, const uint8_t in[64],
                            uint8_t out[64]) {
    uint32x4_t s[4];
    for (size_t lane = 0; lane < 4; ++lane) s[lane] = load_state(in + 16 * lane);
    for (size_t r = 0; r < 32; r += 4) {
        uint32x4_t rk = vld1q_u32(key->rk + r);
        for (size_t lane = 0; lane < 4; ++lane) s[lane] = vsm4eq_u32(s[lane], rk);
    }
    for (size_t lane = 0; lane < 4; ++lane) store_state(out + 16 * lane, s[lane]);
}

#else
void sc_arm_sm4_setkey_hw(sc_sm4_key *key, const uint8_t raw[16]) {
    (void)sc_sm4_setkey(key, raw);
}
void sc_arm_sm4_encrypt4_hw(const sc_sm4_key *key, const uint8_t in[64],
                            uint8_t out[64]) {
    for (size_t i = 0; i < 4; ++i)
        sc_sm4_encrypt_ref(key, in + 16 * i, out + 16 * i);
}
#endif
