#include "internal.h"

#include <stdatomic.h>

/*
 * Four-lane bitsliced GIFT-64-128 core.  A one-block API occupies lane 0;
 * sc_encrypt_blocks can later feed all four lanes without changing the round
 * representation.  The permutation network follows the public MIT-licensed
 * GIFT reference implementation (license recorded in licenses/).
 */
typedef struct {
    uint64_t s0, s1, s2, s3;
} gift_quad;

static const uint8_t gift_rc[28] = {
    0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3b,0x37,0x2f,0x1e,0x3c,0x39,0x33,
    0x27,0x0e,0x1d,0x3a,0x35,0x2b,0x16,0x2c,0x18,0x30,0x21,0x02,0x05,0x0b
};

static uint64_t bit_permute_step(uint64_t x, uint64_t m, unsigned shift) {
    uint64_t t = ((x >> shift) ^ x) & m;
    return (x ^ t) ^ (t << shift);
}

static uint64_t bit_permute_simple(uint64_t x, uint64_t m, unsigned shift) {
    return ((x & m) << shift) | ((x >> shift) & m);
}

static void swapmove(uint64_t *a, uint64_t *b, uint64_t mask,
                     unsigned shift) {
    uint64_t t = (*b ^ (*a >> shift)) & mask;
    *b ^= t;
    *a ^= t << shift;
}

static gift_quad bitslice(const uint64_t input[4]) {
    gift_quad s = {input[0], input[1], input[2], input[3]};
    uint64_t *p[4] = {&s.s0,&s.s1,&s.s2,&s.s3};
    for (size_t i = 0; i < 4; ++i)
        *p[i] = bit_permute_step(*p[i], UINT64_C(0x0a0a0a0a0a0a0a0a), 3);
    for (size_t i = 0; i < 4; ++i)
        *p[i] = bit_permute_step(*p[i], UINT64_C(0x00cc00cc00cc00cc), 6);
    for (size_t i = 0; i < 4; ++i)
        *p[i] = bit_permute_step(*p[i], UINT64_C(0x0000f0f00000f0f0), 12);
    for (size_t i = 0; i < 4; ++i)
        *p[i] = bit_permute_step(*p[i], UINT64_C(0x00000000ff00ff00), 24);
    swapmove(&s.s0, &s.s1, UINT64_C(0x0000ffff0000ffff), 16);
    swapmove(&s.s2, &s.s3, UINT64_C(0x0000ffff0000ffff), 16);
    swapmove(&s.s0, &s.s2, UINT64_C(0x00000000ffffffff), 32);
    swapmove(&s.s1, &s.s3, UINT64_C(0x00000000ffffffff), 32);
    return s;
}

static void unbitslice(gift_quad s, uint64_t output[4]) {
    output[0] = s.s0; output[1] = s.s1;
    output[2] = s.s2; output[3] = s.s3;
    swapmove(&output[1], &output[3], UINT64_C(0x00000000ffffffff), 32);
    swapmove(&output[0], &output[2], UINT64_C(0x00000000ffffffff), 32);
    swapmove(&output[2], &output[3], UINT64_C(0x0000ffff0000ffff), 16);
    swapmove(&output[0], &output[1], UINT64_C(0x0000ffff0000ffff), 16);
    for (size_t i = 0; i < 4; ++i)
        output[i] = bit_permute_step(output[i], UINT64_C(0x00000000ff00ff00), 24);
    for (size_t i = 0; i < 4; ++i)
        output[i] = bit_permute_step(output[i], UINT64_C(0x0000f0f00000f0f0), 12);
    for (size_t i = 0; i < 4; ++i)
        output[i] = bit_permute_step(output[i], UINT64_C(0x00cc00cc00cc00cc), 6);
    for (size_t i = 0; i < 4; ++i)
        output[i] = bit_permute_step(output[i], UINT64_C(0x0a0a0a0a0a0a0a0a), 3);
}

static void sbox(gift_quad *s) {
    s->s1 ^= s->s0 & s->s2;
    s->s0 ^= s->s1 & s->s3;
    s->s2 ^= s->s0 | s->s1;
    s->s3 ^= s->s2;
    s->s1 ^= s->s3;
    s->s3 = ~s->s3;
    s->s2 ^= s->s0 & s->s1;
    s->s0 ^= s->s3;
    s->s3 ^= s->s0;
    s->s0 ^= s->s3;
}

static void inv_sbox(gift_quad *s) {
    s->s0 ^= s->s3;
    s->s3 ^= s->s0;
    s->s0 ^= s->s3;
    s->s2 ^= s->s0 & s->s1;
    s->s3 = ~s->s3;
    s->s1 ^= s->s3;
    s->s3 ^= s->s2;
    s->s2 ^= s->s0 | s->s1;
    s->s0 ^= s->s1 & s->s3;
    s->s1 ^= s->s0 & s->s2;
}

static uint64_t perm0(uint64_t x) {
    return (x & UINT64_C(0x0401040104010401))
        | ((x & UINT64_C(0x0008000800080008)) << 1)
        | ((x & UINT64_C(0x2000200020002000)) << 2)
        | ((x & UINT64_C(0x0040004000400040)) << 3)
        | ((x & UINT64_C(0x0200020002000200)) << 5)
        | ((x & UINT64_C(0x0004000400040004)) << 6)
        | ((x & UINT64_C(0x0020002000200020)) << 8)
        | ((x & UINT64_C(0x0002000200020002)) << 11)
        | ((x & UINT64_C(0x1000100010001000)) >> 9)
        | ((x & UINT64_C(0x8000800080008000)) >> 8)
        | ((x & UINT64_C(0x0100010001000100)) >> 6)
        | ((x & UINT64_C(0x0800080008000800)) >> 5)
        | ((x & UINT64_C(0x4010401040104010)) >> 3)
        | ((x & UINT64_C(0x0080008000800080)) >> 2);
}

static uint64_t perm1(uint64_t x) {
    x = bit_permute_step(x, UINT64_C(0x0a0a0a0a0a0a0a0a), 3);
    x = bit_permute_step(x, UINT64_C(0x00cc00cc00cc00cc), 6);
    return bit_permute_simple(x, UINT64_C(0x0f0f0f0f0f0f0f0f), 4);
}

static uint64_t perm2(uint64_t x) {
    return (x & UINT64_C(0x8020802080208020))
        | ((x & UINT64_C(0x0100010001000100)) << 2)
        | ((x & UINT64_C(0x0802080208020802)) << 3)
        | ((x & UINT64_C(0x0010001000100010)) << 5)
        | ((x & UINT64_C(0x0080008000800080)) << 6)
        | ((x & UINT64_C(0x0001000100010001)) << 8)
        | ((x & UINT64_C(0x0008000800080008)) << 9)
        | ((x & UINT64_C(0x4000400040004000)) >> 11)
        | ((x & UINT64_C(0x0400040004000400)) >> 8)
        | ((x & UINT64_C(0x2000200020002000)) >> 6)
        | ((x & UINT64_C(0x0040004000400040)) >> 5)
        | ((x & UINT64_C(0x0200020002000200)) >> 3)
        | ((x & UINT64_C(0x0004000400040004)) >> 2)
        | ((x & UINT64_C(0x1000100010001000)) >> 1);
}

static uint64_t perm3(uint64_t x) {
    x = bit_permute_step(x, UINT64_C(0x0a0a0a0a0a0a0a0a), 3);
    x = bit_permute_step(x, UINT64_C(0x00cc00cc00cc00cc), 6);
    x = bit_permute_simple(x, UINT64_C(0x0f0f0f0f0f0f0f0f), 4);
    return bit_permute_simple(x, UINT64_C(0x00ff00ff00ff00ff), 8);
}

static void permute(gift_quad *s) {
    s->s0 = perm0(s->s0);
    s->s1 = perm1(s->s1);
    s->s2 = perm2(s->s2);
    s->s3 = perm3(s->s3);
}

static uint8_t inverse_map[4][64];
static atomic_flag map_lock = ATOMIC_FLAG_INIT;
static atomic_int map_ready;

static uint64_t plane_perm(unsigned plane, uint64_t x) {
    if (plane == 0) return perm0(x);
    if (plane == 1) return perm1(x);
    if (plane == 2) return perm2(x);
    return perm3(x);
}

static void init_inverse_map(void) {
    if (atomic_load_explicit(&map_ready, memory_order_acquire)) return;
    while (atomic_flag_test_and_set_explicit(&map_lock, memory_order_acquire)) { }
    if (!atomic_load_explicit(&map_ready, memory_order_relaxed)) {
        for (unsigned p = 0; p < 4; ++p) {
            for (unsigned i = 0; i < 64; ++i) {
                uint64_t y = plane_perm(p, UINT64_C(1) << i);
                inverse_map[p][i] = (uint8_t)__builtin_ctzll(y);
            }
        }
        atomic_store_explicit(&map_ready, 1, memory_order_release);
    }
    atomic_flag_clear_explicit(&map_lock, memory_order_release);
}

static uint64_t inverse_plane(unsigned plane, uint64_t x) {
    uint64_t y = 0;
    for (unsigned i = 0; i < 64; ++i)
        y |= ((x >> inverse_map[plane][i]) & 1U) << i;
    return y;
}

static void inverse_permute(gift_quad *s) {
    init_inverse_map();
    s->s0 = inverse_plane(0, s->s0);
    s->s1 = inverse_plane(1, s->s1);
    s->s2 = inverse_plane(2, s->s2);
    s->s3 = inverse_plane(3, s->s3);
}

static void load_key(const uint8_t key[16], uint16_t w[8]) {
    memset(w, 0, 8 * sizeof(*w));
    for (unsigned i = 0; i < 16; ++i)
        w[7U - i / 2U] |= (uint16_t)key[i] << ((i & 1U) * 8U);
}

static void advance_key(uint16_t w[8]) {
    uint16_t u = w[6], v = w[7];
    memmove(w + 2, w, 6 * sizeof(*w));
    w[0] = (uint16_t)((u >> 2) | (u << 14));
    w[1] = (uint16_t)((v >> 12) | (v << 4));
}

static uint64_t broadcast16(uint16_t x) {
    uint64_t y = x;
    return y | (y << 16) | (y << 32) | (y << 48);
}

void sc_gift_setkey(sc_gift_key *key, const uint8_t raw[16]) {
    memcpy(key->key, raw, 16);
}

void sc_gift_encrypt4(const sc_gift_key *key, const uint8_t in[32],
                      uint8_t out[32]) {
    uint64_t blocks[4];
    for (size_t i = 0; i < 4; ++i) blocks[i] = sc_load_be64(in + 8 * i);
    uint16_t w[8];
    load_key(key->key, w);
    gift_quad s = bitslice(blocks);
    for (unsigned r = 0; r < 28; ++r) {
        sbox(&s);
        permute(&s);
        s.s3 ^= broadcast16((uint16_t)(0x8000U | gift_rc[r]));
        s.s1 ^= broadcast16(w[6]);
        s.s0 ^= broadcast16(w[7]);
        advance_key(w);
    }
    unbitslice(s, blocks);
    for (size_t i = 0; i < 4; ++i) sc_store_be64(out + 8 * i, blocks[i]);
}

void sc_gift_decrypt4(const sc_gift_key *key, const uint8_t in[32],
                      uint8_t out[32]) {
    uint64_t blocks[4];
    for (size_t i = 0; i < 4; ++i) blocks[i] = sc_load_be64(in + 8 * i);
    uint16_t keys[28][8], w[8];
    load_key(key->key, w);
    for (unsigned r = 0; r < 28; ++r) {
        memcpy(keys[r], w, sizeof(w));
        advance_key(w);
    }
    gift_quad s = bitslice(blocks);
    for (int r = 27; r >= 0; --r) {
        s.s1 ^= broadcast16(keys[r][6]);
        s.s0 ^= broadcast16(keys[r][7]);
        s.s3 ^= broadcast16((uint16_t)(0x8000U | gift_rc[r]));
        inverse_permute(&s);
        inv_sbox(&s);
    }
    unbitslice(s, blocks);
    for (size_t i = 0; i < 4; ++i) sc_store_be64(out + 8 * i, blocks[i]);
}

void sc_gift_encrypt(const sc_gift_key *key, const uint8_t in[8],
                     uint8_t out[8]) {
    uint8_t lanes[32] = {0};
    memcpy(lanes, in, 8);
    sc_gift_encrypt4(key, lanes, lanes);
    memcpy(out, lanes, 8);
}

void sc_gift_decrypt(const sc_gift_key *key, const uint8_t in[8],
                     uint8_t out[8]) {
    uint8_t lanes[32] = {0};
    memcpy(lanes, in, 8);
    sc_gift_decrypt4(key, lanes, lanes);
    memcpy(out, lanes, 8);
}
