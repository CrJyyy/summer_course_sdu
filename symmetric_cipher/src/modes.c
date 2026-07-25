#include "internal.h"

#include <stdlib.h>

static int ctx_ok(const sc_ctx *ctx) {
    return ctx != NULL && sc_const(ctx)->magic == SC_MAGIC;
}

static int increment_be(uint8_t *counter, size_t n) {
    for (size_t i = n; i-- > 0;) {
        counter[i]++;
        if (counter[i] != 0) return 1;
    }
    return 0;
}

sc_status sc_ctr_xor(const sc_ctx *ctx, uint8_t *counter, const uint8_t *in,
                     uint8_t *out, size_t len) {
    if (!ctx_ok(ctx) || counter == NULL || (len && (in == NULL || out == NULL)))
        return SC_ERR_ARGUMENT;
    size_t bs = sc_block_size(ctx);
    enum { CTR_LANES = 8 };
    uint8_t probe[SC_MAX_BLOCK], counters[CTR_LANES * SC_MAX_BLOCK];
    uint8_t stream[CTR_LANES * SC_MAX_BLOCK];
    size_t blocks = (len + bs - 1U) / bs;
    memcpy(probe, counter, bs);
    for (size_t i = 0; i < blocks; ++i)
        if (!increment_be(probe, bs)) return SC_ERR_COUNTER_WRAP;
    size_t off = 0;
    while (off < len) {
        size_t remaining_blocks = (len - off + bs - 1U) / bs;
        size_t lanes = remaining_blocks < CTR_LANES ? remaining_blocks : CTR_LANES;
        for (size_t lane = 0; lane < lanes; ++lane) {
            memcpy(counters + lane * bs, counter, bs);
            (void)increment_be(counter, bs);
        }
        sc_status rc = sc_encrypt_blocks(ctx, counters, stream, lanes);
        if (rc != SC_OK) return rc;
        size_t take = len - off < lanes * bs ? len - off : lanes * bs;
        for (size_t i = 0; i < take; ++i)
            out[off + i] = (uint8_t)(in[off + i] ^ stream[i]);
        off += take;
    }
    return SC_OK;
}

static void xor16(uint8_t a[16], const uint8_t b[16]) {
    for (size_t i = 0; i < 16; ++i) a[i] ^= b[i];
}

static void shift_right_one(uint8_t v[16]) {
    uint8_t carry = 0;
    for (size_t i = 0; i < 16; ++i) {
        uint8_t next = (uint8_t)(v[i] & 1U);
        v[i] = (uint8_t)((v[i] >> 1) | (carry << 7));
        carry = next;
    }
}

static void ghash_mul_scalar(uint8_t x[16], const uint8_t h[16]) {
    uint8_t z[16] = {0}, v[16];
    memcpy(v, h, 16);
    for (size_t i = 0; i < 128; ++i) {
        uint8_t bit = (uint8_t)((x[i / 8] >> (7U - (i & 7U))) & 1U);
        uint8_t mask = (uint8_t)(0U - bit);
        for (size_t j = 0; j < 16; ++j) z[j] ^= (uint8_t)(v[j] & mask);
        uint8_t lsb = (uint8_t)(v[15] & 1U);
        shift_right_one(v);
        v[0] ^= (uint8_t)(0xe1U & (uint8_t)(0U - lsb));
    }
    memcpy(x, z, 16);
}

static void ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    if (!sc_arm_ghash_mul(x, h) && !sc_x86_ghash_mul(x, h))
        ghash_mul_scalar(x, h);
}

static void ghash_bytes(uint8_t y[16], const uint8_t h[16],
                        const uint8_t *data, size_t len) {
    if (len >= 64) {
        uint8_t h2[16], h3[16], h4[16];
        memcpy(h2, h, 16); ghash_mul(h2, h);
        memcpy(h3, h2, 16); ghash_mul(h3, h);
        memcpy(h4, h3, 16); ghash_mul(h4, h);
        while (len >= 64) {
            uint8_t terms[4][16];
            memcpy(terms[0], y, 16);
            xor16(terms[0], data);
            memcpy(terms[1], data + 16, 16);
            memcpy(terms[2], data + 32, 16);
            memcpy(terms[3], data + 48, 16);
            ghash_mul(terms[0], h4);
            ghash_mul(terms[1], h3);
            ghash_mul(terms[2], h2);
            ghash_mul(terms[3], h);
            memcpy(y, terms[0], 16);
            xor16(y, terms[1]);
            xor16(y, terms[2]);
            xor16(y, terms[3]);
            data += 64;
            len -= 64;
        }
    }
    while (len >= 16) {
        xor16(y, data);
        ghash_mul(y, h);
        data += 16;
        len -= 16;
    }
    if (len) {
        uint8_t last[16] = {0};
        memcpy(last, data, len);
        xor16(y, last);
        ghash_mul(y, h);
    }
}

static void store_be64_local(uint8_t p[8], uint64_t x) {
    sc_store_be32(p, (uint32_t)(x >> 32));
    sc_store_be32(p + 4, (uint32_t)x);
}

static sc_status make_j0(const sc_ctx *ctx, const uint8_t h[16],
                         const uint8_t *iv, size_t iv_len, uint8_t j0[16]) {
    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        memset(j0 + 12, 0, 3);
        j0[15] = 1;
        return SC_OK;
    }
    if (iv_len > UINT64_MAX / 8U) return SC_ERR_ARGUMENT;
    memset(j0, 0, 16);
    ghash_bytes(j0, h, iv, iv_len);
    uint8_t lengths[16] = {0};
    store_be64_local(lengths + 8, (uint64_t)iv_len * 8U);
    xor16(j0, lengths);
    ghash_mul(j0, h);
    (void)ctx;
    return SC_OK;
}

static int inc32(uint8_t counter[16]) {
    return increment_be(counter + 12, 4);
}

static int gcm_counter_fits(const uint8_t j0[16], size_t blocks) {
    uint8_t probe[16];
    memcpy(probe, j0, 16);
    for (size_t i = 0; i < blocks; ++i)
        if (!inc32(probe)) return 0;
    return 1;
}

static sc_status gcm_tag(const sc_ctx *ctx, const uint8_t h[16],
                         const uint8_t j0[16], const uint8_t *aad,
                         size_t aad_len, const uint8_t *ciphertext,
                         size_t len, uint8_t tag[16]) {
    if (aad_len > UINT64_MAX / 8U || len > UINT64_MAX / 8U)
        return SC_ERR_ARGUMENT;
    uint8_t y[16] = {0}, e0[16], lengths[16];
    ghash_bytes(y, h, aad, aad_len);
    ghash_bytes(y, h, ciphertext, len);
    store_be64_local(lengths, (uint64_t)aad_len * 8U);
    store_be64_local(lengths + 8, (uint64_t)len * 8U);
    xor16(y, lengths);
    ghash_mul(y, h);
    sc_status rc = sc_encrypt_block(ctx, j0, e0);
    if (rc != SC_OK) return rc;
    for (size_t i = 0; i < 16; ++i) tag[i] = (uint8_t)(e0[i] ^ y[i]);
    return SC_OK;
}

static sc_status gcm_check(const sc_ctx *ctx, const uint8_t *iv, size_t iv_len,
                           size_t tag_len, uint8_t h[16], uint8_t j0[16]) {
    if (!ctx_ok(ctx) || sc_block_size(ctx) != 16 ||
        (sc_algorithm_id(ctx) != SC_AES_128 &&
         sc_algorithm_id(ctx) != SC_AES_192 &&
         sc_algorithm_id(ctx) != SC_AES_256 &&
         sc_algorithm_id(ctx) != SC_SM4_128))
        return SC_ERR_UNSUPPORTED;
    if (iv == NULL || tag_len == 0 || tag_len > 16) return SC_ERR_ARGUMENT;
    uint8_t zero[16] = {0};
    sc_status rc = sc_encrypt_block(ctx, zero, h);
    if (rc != SC_OK) return rc;
    return make_j0(ctx, h, iv, iv_len, j0);
}

sc_status sc_gcm_encrypt(const sc_ctx *ctx, const uint8_t *iv, size_t iv_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, uint8_t *ciphertext,
                         size_t len, uint8_t *tag, size_t tag_len) {
    if ((aad_len && aad == NULL) || (len && (plaintext == NULL || ciphertext == NULL)) ||
        tag == NULL) return SC_ERR_ARGUMENT;
    enum { GCM_LANES = 8 };
    uint8_t h[16], j0[16], counter[16], counters[GCM_LANES * 16];
    uint8_t stream[GCM_LANES * 16], full_tag[16];
    sc_status rc = gcm_check(ctx, iv, iv_len, tag_len, h, j0);
    if (rc != SC_OK) return rc;
    size_t blocks = (len + 15U) / 16U;
    if (!gcm_counter_fits(j0, blocks)) return SC_ERR_COUNTER_WRAP;
    memcpy(counter, j0, 16);
    for (size_t off = 0; off < len;) {
        size_t left = (len - off + 15U) / 16U;
        size_t lanes = left < GCM_LANES ? left : GCM_LANES;
        for (size_t lane = 0; lane < lanes; ++lane) {
            (void)inc32(counter);
            memcpy(counters + lane * 16, counter, 16);
        }
        rc = sc_encrypt_blocks(ctx, counters, stream, lanes);
        if (rc != SC_OK) return rc;
        size_t take = len - off < lanes * 16 ? len - off : lanes * 16;
        for (size_t i = 0; i < take; ++i)
            ciphertext[off + i] = (uint8_t)(plaintext[off + i] ^ stream[i]);
        off += take;
    }
    rc = gcm_tag(ctx, h, j0, aad, aad_len, ciphertext, len, full_tag);
    if (rc == SC_OK) memcpy(tag, full_tag, tag_len);
    return rc;
}

sc_status sc_gcm_decrypt(const sc_ctx *ctx, const uint8_t *iv, size_t iv_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, uint8_t *plaintext,
                         size_t len, const uint8_t *tag, size_t tag_len) {
    if ((aad_len && aad == NULL) || (len && (ciphertext == NULL || plaintext == NULL)) ||
        tag == NULL) return SC_ERR_ARGUMENT;
    enum { GCM_LANES = 8 };
    uint8_t h[16], j0[16], expected[16], counter[16];
    uint8_t counters[GCM_LANES * 16], stream[GCM_LANES * 16];
    sc_status rc = gcm_check(ctx, iv, iv_len, tag_len, h, j0);
    if (rc != SC_OK) return rc;
    rc = gcm_tag(ctx, h, j0, aad, aad_len, ciphertext, len, expected);
    if (rc != SC_OK) return rc;
    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; ++i) diff |= (uint8_t)(expected[i] ^ tag[i]);
    if (diff != 0) {
        if (plaintext != NULL) memset(plaintext, 0, len);
        return SC_ERR_AUTH;
    }
    size_t blocks = (len + 15U) / 16U;
    if (!gcm_counter_fits(j0, blocks)) {
        memset(plaintext, 0, len);
        return SC_ERR_COUNTER_WRAP;
    }
    memcpy(counter, j0, 16);
    for (size_t off = 0; off < len;) {
        size_t left = (len - off + 15U) / 16U;
        size_t lanes = left < GCM_LANES ? left : GCM_LANES;
        for (size_t lane = 0; lane < lanes; ++lane) {
            (void)inc32(counter);
            memcpy(counters + lane * 16, counter, 16);
        }
        rc = sc_encrypt_blocks(ctx, counters, stream, lanes);
        if (rc != SC_OK) {
            memset(plaintext, 0, len);
            return rc;
        }
        size_t take = len - off < lanes * 16 ? len - off : lanes * 16;
        for (size_t i = 0; i < take; ++i)
            plaintext[off + i] = (uint8_t)(ciphertext[off + i] ^ stream[i]);
        off += take;
    }
    return SC_OK;
}

static void xts_mul_x(uint8_t t[16], sc_xts_convention convention) {
    uint8_t carry = 0;
    if (convention == SC_XTS_IEEE_LE) {
        for (size_t i = 0; i < 16; ++i) {
            uint8_t next = (uint8_t)(t[i] >> 7);
            t[i] = (uint8_t)((t[i] << 1) | carry);
            carry = next;
        }
        t[0] ^= (uint8_t)(0x87U & (uint8_t)(0U - carry));
    } else {
        for (size_t i = 0; i < 16; ++i) {
            uint8_t next = (uint8_t)(t[i] & 1U);
            t[i] = (uint8_t)((t[i] >> 1) | (carry << 7));
            carry = next;
        }
        t[0] ^= (uint8_t)(0xe1U & (uint8_t)(0U - carry));
    }
}

static sc_status xts_validate(const sc_ctx *data_ctx, const sc_ctx *tweak_ctx,
                              size_t len, sc_xts_convention convention) {
    if (!ctx_ok(data_ctx) || !ctx_ok(tweak_ctx)) return SC_ERR_ARGUMENT;
    if (len < 16) return SC_ERR_DATA_UNIT;
    if (sc_block_size(data_ctx) != 16 || sc_block_size(tweak_ctx) != 16 ||
        sc_algorithm_id(data_ctx) != sc_algorithm_id(tweak_ctx))
        return SC_ERR_UNSUPPORTED;
    if (convention != SC_XTS_IEEE_LE && convention != SC_XTS_GBT_BE)
        return SC_ERR_ARGUMENT;
    return SC_OK;
}

static sc_status xex_block(const sc_ctx *ctx, int decrypt,
                           const uint8_t in[16], uint8_t out[16],
                           const uint8_t t[16]) {
    uint8_t x[16];
    for (size_t i = 0; i < 16; ++i) x[i] = (uint8_t)(in[i] ^ t[i]);
    sc_status rc = decrypt ? sc_decrypt_block(ctx, x, x) : sc_encrypt_block(ctx, x, x);
    if (rc != SC_OK) return rc;
    for (size_t i = 0; i < 16; ++i) out[i] = (uint8_t)(x[i] ^ t[i]);
    return SC_OK;
}

sc_status sc_xts_encrypt(const sc_ctx *data_ctx, const sc_ctx *tweak_ctx,
                         const uint8_t tweak[16], const uint8_t *plaintext,
                         uint8_t *ciphertext, size_t len,
                         sc_xts_convention convention) {
    sc_status rc = xts_validate(data_ctx, tweak_ctx, len, convention);
    if (rc != SC_OK || tweak == NULL || plaintext == NULL || ciphertext == NULL)
        return rc == SC_OK ? SC_ERR_ARGUMENT : rc;
    enum { XTS_LANES = 8 };
    uint8_t t[16], cc[16], pp[16], tail_plain[16];
    uint8_t tweaks[XTS_LANES * 16], work[XTS_LANES * 16];
    rc = sc_encrypt_block(tweak_ctx, tweak, t);
    if (rc != SC_OK) return rc;
    size_t full = len / 16, tail = len % 16;
    size_t ordinary = tail ? full - 1 : full;
    for (size_t b = 0; b < ordinary;) {
        size_t lanes = ordinary - b < XTS_LANES ? ordinary - b : XTS_LANES;
        for (size_t lane = 0; lane < lanes; ++lane) {
            memcpy(tweaks + 16 * lane, t, 16);
            for (size_t i = 0; i < 16; ++i)
                work[16 * lane + i] =
                    (uint8_t)(plaintext[16 * (b + lane) + i] ^ t[i]);
            xts_mul_x(t, convention);
        }
        rc = sc_encrypt_blocks(data_ctx, work, work, lanes);
        if (rc != SC_OK) return rc;
        for (size_t lane = 0; lane < lanes; ++lane)
            for (size_t i = 0; i < 16; ++i)
                ciphertext[16 * (b + lane) + i] =
                    (uint8_t)(work[16 * lane + i] ^ tweaks[16 * lane + i]);
        b += lanes;
    }
    if (!tail) return SC_OK;
    const uint8_t *last = plaintext + 16 * ordinary;
    memcpy(tail_plain, plaintext + 16 * full, tail);
    rc = xex_block(data_ctx, 0, last, cc, t);
    if (rc != SC_OK) return rc;
    memcpy(ciphertext + 16 * full, cc, tail);
    memcpy(pp, tail_plain, tail);
    memcpy(pp + tail, cc + tail, 16 - tail);
    xts_mul_x(t, convention);
    return xex_block(data_ctx, 0, pp, ciphertext + 16 * ordinary, t);
}

sc_status sc_xts_decrypt(const sc_ctx *data_ctx, const sc_ctx *tweak_ctx,
                         const uint8_t tweak[16], const uint8_t *ciphertext,
                         uint8_t *plaintext, size_t len,
                         sc_xts_convention convention) {
    sc_status rc = xts_validate(data_ctx, tweak_ctx, len, convention);
    if (rc != SC_OK || tweak == NULL || plaintext == NULL || ciphertext == NULL)
        return rc == SC_OK ? SC_ERR_ARGUMENT : rc;
    enum { XTS_LANES = 8 };
    uint8_t t[16], next[16], pp[16], cc[16], tail_cipher[16];
    uint8_t tweaks[XTS_LANES * 16], work[XTS_LANES * 16];
    rc = sc_encrypt_block(tweak_ctx, tweak, t);
    if (rc != SC_OK) return rc;
    size_t full = len / 16, tail = len % 16;
    size_t ordinary = tail ? full - 1 : full;
    for (size_t b = 0; b < ordinary;) {
        size_t lanes = ordinary - b < XTS_LANES ? ordinary - b : XTS_LANES;
        for (size_t lane = 0; lane < lanes; ++lane) {
            memcpy(tweaks + 16 * lane, t, 16);
            for (size_t i = 0; i < 16; ++i)
                work[16 * lane + i] =
                    (uint8_t)(ciphertext[16 * (b + lane) + i] ^ t[i]);
            xts_mul_x(t, convention);
        }
        rc = sc_decrypt_blocks(data_ctx, work, work, lanes);
        if (rc != SC_OK) return rc;
        for (size_t lane = 0; lane < lanes; ++lane)
            for (size_t i = 0; i < 16; ++i)
                plaintext[16 * (b + lane) + i] =
                    (uint8_t)(work[16 * lane + i] ^ tweaks[16 * lane + i]);
        b += lanes;
    }
    if (!tail) return SC_OK;
    memcpy(next, t, 16);
    xts_mul_x(next, convention);
    memcpy(tail_cipher, ciphertext + 16 * full, tail);
    rc = xex_block(data_ctx, 1, ciphertext + 16 * ordinary, pp, next);
    if (rc != SC_OK) return rc;
    memcpy(plaintext + 16 * full, pp, tail);
    memcpy(cc, tail_cipher, tail);
    memcpy(cc + tail, pp + tail, 16 - tail);
    return xex_block(data_ctx, 1, cc, plaintext + 16 * ordinary, t);
}

sc_status sc_xts_tweak_from_data_unit(uint64_t data_unit_no,
                                      sc_xts_convention convention,
                                      uint8_t tweak[16]) {
    if (tweak == NULL ||
        (convention != SC_XTS_IEEE_LE && convention != SC_XTS_GBT_BE))
        return SC_ERR_ARGUMENT;
    memset(tweak, 0, 16);
    if (convention == SC_XTS_IEEE_LE) {
        for (size_t i = 0; i < 8; ++i)
            tweak[i] = (uint8_t)(data_unit_no >> (8U * i));
    } else {
        for (size_t i = 0; i < 8; ++i)
            tweak[15U - i] = (uint8_t)(data_unit_no >> (8U * i));
    }
    return SC_OK;
}
