#include "internal.h"

static const uint8_t sbox[16] = {
    0x0c,0x00,0x0f,0x0a,0x02,0x0b,0x09,0x05,
    0x08,0x03,0x0d,0x07,0x01,0x0e,0x06,0x04
};

static const uint8_t perm[16] = {
    5,0,1,4,7,12,3,8,13,6,9,2,15,10,11,14
};

static const uint8_t inv_perm[16] = {
    1,2,11,6,3,0,9,4,7,10,13,14,5,8,15,12
};

static const uint8_t rc[35] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x03,0x06,0x0c,0x18,0x30,0x23,
    0x05,0x0a,0x14,0x28,0x13,0x26,0x0f,0x1e,0x3c,0x3b,0x35,0x29,
    0x11,0x22,0x07,0x0e,0x1c,0x38,0x33,0x25,0x09,0x12,0x24
};

static void extract80(uint8_t rk[8], const uint8_t w[20]) {
    static const uint8_t pos[8] = {1,3,4,6,13,14,15,16};
    for (size_t i = 0; i < 8; ++i) rk[i] = w[pos[i]];
}

static void extract128(uint8_t rk[8], const uint8_t w[32]) {
    static const uint8_t pos[8] = {2,3,12,15,17,18,28,31};
    for (size_t i = 0; i < 8; ++i) rk[i] = w[pos[i]];
}

static void rotate_key(uint8_t *w, size_t n) {
    uint8_t t[4] = {w[0], w[1], w[2], w[3]};
    memmove(w, w + 4, n - 4);
    w[n - 4] = t[1];
    w[n - 3] = t[2];
    w[n - 2] = t[3];
    w[n - 1] = t[0];
}

sc_status sc_twine_setkey(sc_twine_key *key, const uint8_t *raw, size_t len) {
    if (len != 10 && len != 16) return SC_ERR_KEY_SIZE;
    uint8_t w[32] = {0};
    for (size_t i = 0; i < len; ++i) {
        w[2 * i] = (uint8_t)(raw[i] >> 4);
        w[2 * i + 1] = (uint8_t)(raw[i] & 15);
    }
    for (size_t r = 0; r < 35; ++r) {
        if (len == 10) extract80(key->rk[r], w);
        else extract128(key->rk[r], w);
        w[1] ^= sbox[w[0]];
        w[4] ^= sbox[w[16]];
        if (len == 16) w[23] ^= sbox[w[30]];
        w[7] ^= (uint8_t)(rc[r] >> 3);
        w[19] ^= (uint8_t)(rc[r] & 7);
        rotate_key(w, 2 * len);
    }
    if (len == 10) extract80(key->rk[35], w);
    else extract128(key->rk[35], w);
    return SC_OK;
}

static void unpack(const uint8_t in[8], uint8_t x[16]) {
    for (size_t i = 0; i < 8; ++i) {
        x[2 * i] = (uint8_t)(in[i] >> 4);
        x[2 * i + 1] = (uint8_t)(in[i] & 15);
    }
}

static void pack(const uint8_t x[16], uint8_t out[8]) {
    for (size_t i = 0; i < 8; ++i)
        out[i] = (uint8_t)((x[2 * i] << 4) | x[2 * i + 1]);
}

void sc_twine_encrypt(const sc_twine_key *key, const uint8_t in[8],
                      uint8_t out[8]) {
    uint8_t x[16], y[16];
    unpack(in, x);
    for (size_t r = 0; r < 35; ++r) {
        for (size_t j = 0; j < 8; ++j)
            x[2 * j + 1] ^= sbox[x[2 * j] ^ key->rk[r][j]];
        for (size_t j = 0; j < 16; ++j) y[perm[j]] = x[j];
        memcpy(x, y, sizeof(x));
    }
    for (size_t j = 0; j < 8; ++j)
        x[2 * j + 1] ^= sbox[x[2 * j] ^ key->rk[35][j]];
    pack(x, out);
}

void sc_twine_decrypt(const sc_twine_key *key, const uint8_t in[8],
                      uint8_t out[8]) {
    uint8_t x[16], y[16];
    unpack(in, x);
    for (int r = 35; r >= 1; --r) {
        for (size_t j = 0; j < 8; ++j)
            x[2 * j + 1] ^= sbox[x[2 * j] ^ key->rk[r][j]];
        for (size_t j = 0; j < 16; ++j) y[inv_perm[j]] = x[j];
        memcpy(x, y, sizeof(x));
    }
    for (size_t j = 0; j < 8; ++j)
        x[2 * j + 1] ^= sbox[x[2 * j] ^ key->rk[0][j]];
    pack(x, out);
}
