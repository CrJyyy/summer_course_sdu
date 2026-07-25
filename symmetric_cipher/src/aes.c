#include "internal.h"

#include <stdatomic.h>

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t aes_inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

uint8_t sc_aes_inv_sbox_byte(uint8_t x) {
    return aes_inv_sbox[x];
}

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1bU));
}

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (unsigned i = 0; i < 8; ++i) {
        r ^= (uint8_t)(a * (b & 1U));
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

static void sub_bytes(uint8_t s[16]) {
    for (size_t i = 0; i < 16; ++i) s[i] = aes_sbox[s[i]];
}

static void inv_sub_bytes(uint8_t s[16]) {
    for (size_t i = 0; i < 16; ++i) s[i] = aes_inv_sbox[s[i]];
}

static void shift_rows(uint8_t s[16]) {
    uint8_t t[16];
    for (size_t r = 0; r < 4; ++r)
        for (size_t c = 0; c < 4; ++c)
            t[4 * c + r] = s[4 * ((c + r) & 3U) + r];
    memcpy(s, t, sizeof(t));
}

static void inv_shift_rows(uint8_t s[16]) {
    uint8_t t[16];
    for (size_t r = 0; r < 4; ++r)
        for (size_t c = 0; c < 4; ++c)
            t[4 * c + r] = s[4 * ((c + 4U - r) & 3U) + r];
    memcpy(s, t, sizeof(t));
}

static void mix_columns(uint8_t s[16]) {
    for (size_t c = 0; c < 4; ++c) {
        uint8_t *p = s + 4 * c;
        uint8_t a = p[0], b = p[1], d = p[2], e = p[3];
        p[0] = (uint8_t)(xtime(a) ^ (xtime(b) ^ b) ^ d ^ e);
        p[1] = (uint8_t)(a ^ xtime(b) ^ (xtime(d) ^ d) ^ e);
        p[2] = (uint8_t)(a ^ b ^ xtime(d) ^ (xtime(e) ^ e));
        p[3] = (uint8_t)((xtime(a) ^ a) ^ b ^ d ^ xtime(e));
    }
}

static void inv_mix_columns(uint8_t s[16]) {
    for (size_t c = 0; c < 4; ++c) {
        uint8_t *p = s + 4 * c;
        uint8_t a = p[0], b = p[1], d = p[2], e = p[3];
        p[0] = (uint8_t)(gf_mul(a,14) ^ gf_mul(b,11) ^ gf_mul(d,13) ^ gf_mul(e,9));
        p[1] = (uint8_t)(gf_mul(a,9) ^ gf_mul(b,14) ^ gf_mul(d,11) ^ gf_mul(e,13));
        p[2] = (uint8_t)(gf_mul(a,13) ^ gf_mul(b,9) ^ gf_mul(d,14) ^ gf_mul(e,11));
        p[3] = (uint8_t)(gf_mul(a,11) ^ gf_mul(b,13) ^ gf_mul(d,9) ^ gf_mul(e,14));
    }
}

static void add_round_key(uint8_t s[16], const uint8_t *rk) {
    for (size_t i = 0; i < 16; ++i) s[i] ^= rk[i];
}

sc_status sc_aes_setkey(sc_aes_key *key, const uint8_t *raw, size_t len) {
    if (len != 16 && len != 24 && len != 32) return SC_ERR_KEY_SIZE;
    int nk = (int)(len / 4);
    key->rounds = nk + 6;
    size_t total = (size_t)16 * (size_t)(key->rounds + 1);
    memcpy(key->round_key, raw, len);
    uint8_t rcon = 1;
    size_t generated = len;
    uint8_t temp[4];
    while (generated < total) {
        memcpy(temp, key->round_key + generated - 4, 4);
        if (generated % len == 0) {
            uint8_t q = temp[0];
            temp[0] = (uint8_t)(aes_sbox[temp[1]] ^ rcon);
            temp[1] = aes_sbox[temp[2]];
            temp[2] = aes_sbox[temp[3]];
            temp[3] = aes_sbox[q];
            rcon = xtime(rcon);
        } else if (nk > 6 && generated % len == 16) {
            for (size_t i = 0; i < 4; ++i) temp[i] = aes_sbox[temp[i]];
        }
        for (size_t i = 0; i < 4 && generated < total; ++i, ++generated)
            key->round_key[generated] =
                (uint8_t)(key->round_key[generated - len] ^ temp[i]);
    }
    return SC_OK;
}

void sc_aes_encrypt_ref(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    add_round_key(s, key->round_key);
    for (int r = 1; r < key->rounds; ++r) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, key->round_key + 16 * r);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, key->round_key + 16 * key->rounds);
    memcpy(out, s, 16);
}

void sc_aes_decrypt_ref(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    add_round_key(s, key->round_key + 16 * key->rounds);
    for (int r = key->rounds - 1; r > 0; --r) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, key->round_key + 16 * r);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, key->round_key);
    memcpy(out, s, 16);
}

static uint32_t te[4][256], td[4][256];
static atomic_flag te_lock = ATOMIC_FLAG_INIT;
static atomic_int te_ready;

static void init_te(void) {
    if (atomic_load_explicit(&te_ready, memory_order_acquire)) return;
    while (atomic_flag_test_and_set_explicit(&te_lock, memory_order_acquire)) { }
    if (!atomic_load_explicit(&te_ready, memory_order_relaxed)) {
        for (unsigned i = 0; i < 256; ++i) {
            uint8_t s = aes_sbox[i];
            uint32_t x = ((uint32_t)xtime(s) << 24) | ((uint32_t)s << 16) |
                         ((uint32_t)s << 8) | (uint32_t)(xtime(s) ^ s);
            te[0][i] = x;
            te[1][i] = (x >> 8) | (x << 24);
            te[2][i] = (x >> 16) | (x << 16);
            te[3][i] = (x >> 24) | (x << 8);
            s = aes_inv_sbox[i];
            x = ((uint32_t)gf_mul(s, 14) << 24) |
                ((uint32_t)gf_mul(s, 9) << 16) |
                ((uint32_t)gf_mul(s, 13) << 8) |
                (uint32_t)gf_mul(s, 11);
            td[0][i] = x;
            td[1][i] = (x >> 8) | (x << 24);
            td[2][i] = (x >> 16) | (x << 16);
            td[3][i] = (x >> 24) | (x << 8);
        }
        atomic_store_explicit(&te_ready, 1, memory_order_release);
    }
    atomic_flag_clear_explicit(&te_lock, memory_order_release);
}

static uint32_t inv_mix_word(uint32_t x) {
    uint8_t a = (uint8_t)(x >> 24), b = (uint8_t)(x >> 16);
    uint8_t c = (uint8_t)(x >> 8), d = (uint8_t)x;
    return ((uint32_t)(gf_mul(a,14) ^ gf_mul(b,11) ^
                       gf_mul(c,13) ^ gf_mul(d,9)) << 24) |
           ((uint32_t)(gf_mul(a,9) ^ gf_mul(b,14) ^
                       gf_mul(c,11) ^ gf_mul(d,13)) << 16) |
           ((uint32_t)(gf_mul(a,13) ^ gf_mul(b,9) ^
                       gf_mul(c,14) ^ gf_mul(d,11)) << 8) |
           (uint32_t)(gf_mul(a,11) ^ gf_mul(b,13) ^
                      gf_mul(c,9) ^ gf_mul(d,14));
}

void sc_aes_decrypt_ttable(const sc_aes_key *key, const uint8_t in[16],
                           uint8_t out[16]) {
    init_te();
    uint32_t s[4], t[4];
    const uint8_t *last = key->round_key + 16 * key->rounds;
    for (size_t i = 0; i < 4; ++i)
        s[i] = sc_load_be32(in + 4 * i) ^ sc_load_be32(last + 4 * i);
    for (int r = key->rounds - 1; r > 0; --r) {
        const uint8_t *rk = key->round_key + 16 * r;
        t[0] = td[0][s[0] >> 24] ^ td[1][(s[3] >> 16) & 255] ^
               td[2][(s[2] >> 8) & 255] ^ td[3][s[1] & 255] ^
               inv_mix_word(sc_load_be32(rk));
        t[1] = td[0][s[1] >> 24] ^ td[1][(s[0] >> 16) & 255] ^
               td[2][(s[3] >> 8) & 255] ^ td[3][s[2] & 255] ^
               inv_mix_word(sc_load_be32(rk + 4));
        t[2] = td[0][s[2] >> 24] ^ td[1][(s[1] >> 16) & 255] ^
               td[2][(s[0] >> 8) & 255] ^ td[3][s[3] & 255] ^
               inv_mix_word(sc_load_be32(rk + 8));
        t[3] = td[0][s[3] >> 24] ^ td[1][(s[2] >> 16) & 255] ^
               td[2][(s[1] >> 8) & 255] ^ td[3][s[0] & 255] ^
               inv_mix_word(sc_load_be32(rk + 12));
        memcpy(s, t, sizeof(s));
    }
    const uint8_t *rk = key->round_key;
    uint8_t q[16] = {
        aes_inv_sbox[s[0] >> 24], aes_inv_sbox[(s[3] >> 16) & 255],
        aes_inv_sbox[(s[2] >> 8) & 255], aes_inv_sbox[s[1] & 255],
        aes_inv_sbox[s[1] >> 24], aes_inv_sbox[(s[0] >> 16) & 255],
        aes_inv_sbox[(s[3] >> 8) & 255], aes_inv_sbox[s[2] & 255],
        aes_inv_sbox[s[2] >> 24], aes_inv_sbox[(s[1] >> 16) & 255],
        aes_inv_sbox[(s[0] >> 8) & 255], aes_inv_sbox[s[3] & 255],
        aes_inv_sbox[s[3] >> 24], aes_inv_sbox[(s[2] >> 16) & 255],
        aes_inv_sbox[(s[1] >> 8) & 255], aes_inv_sbox[s[0] & 255]
    };
    for (size_t i = 0; i < 16; ++i) out[i] = (uint8_t)(q[i] ^ rk[i]);
}

void sc_aes_encrypt_ttable(const sc_aes_key *key, const uint8_t in[16],
                           uint8_t out[16]) {
    init_te();
    uint32_t s[4], t[4];
    for (size_t i = 0; i < 4; ++i)
        s[i] = sc_load_be32(in + 4 * i) ^ sc_load_be32(key->round_key + 4 * i);
    for (int r = 1; r < key->rounds; ++r) {
        const uint8_t *rk = key->round_key + 16 * r;
        t[0] = te[0][s[0] >> 24] ^ te[1][(s[1] >> 16) & 255] ^
               te[2][(s[2] >> 8) & 255] ^ te[3][s[3] & 255] ^ sc_load_be32(rk);
        t[1] = te[0][s[1] >> 24] ^ te[1][(s[2] >> 16) & 255] ^
               te[2][(s[3] >> 8) & 255] ^ te[3][s[0] & 255] ^ sc_load_be32(rk + 4);
        t[2] = te[0][s[2] >> 24] ^ te[1][(s[3] >> 16) & 255] ^
               te[2][(s[0] >> 8) & 255] ^ te[3][s[1] & 255] ^ sc_load_be32(rk + 8);
        t[3] = te[0][s[3] >> 24] ^ te[1][(s[0] >> 16) & 255] ^
               te[2][(s[1] >> 8) & 255] ^ te[3][s[2] & 255] ^ sc_load_be32(rk + 12);
        memcpy(s, t, sizeof(s));
    }
    const uint8_t *rk = key->round_key + 16 * key->rounds;
    uint8_t q[16] = {
        aes_sbox[s[0] >> 24], aes_sbox[(s[1] >> 16) & 255], aes_sbox[(s[2] >> 8) & 255], aes_sbox[s[3] & 255],
        aes_sbox[s[1] >> 24], aes_sbox[(s[2] >> 16) & 255], aes_sbox[(s[3] >> 8) & 255], aes_sbox[s[0] & 255],
        aes_sbox[s[2] >> 24], aes_sbox[(s[3] >> 16) & 255], aes_sbox[(s[0] >> 8) & 255], aes_sbox[s[1] & 255],
        aes_sbox[s[3] >> 24], aes_sbox[(s[0] >> 16) & 255], aes_sbox[(s[1] >> 8) & 255], aes_sbox[s[2] & 255]
    };
    for (size_t i = 0; i < 16; ++i) out[i] = (uint8_t)(q[i] ^ rk[i]);
}
