#include "symcrypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern uint8_t sc_sm4_gfni_scalar_model(uint8_t x);

static unsigned tests_run;
static unsigned tests_failed;

#define CHECK(cond) do { \
    ++tests_run; \
    if (!(cond)) { \
        ++tests_failed; \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    } \
} while (0)

static size_t unhex(const char *hex, uint8_t *out) {
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; ++i) {
        unsigned x;
        if (sscanf(hex + 2 * i, "%2x", &x) != 1) abort();
        out[i] = (uint8_t)x;
    }
    return n;
}

static void kat(sc_algorithm alg, sc_backend backend, const char *key_hex,
                const char *pt_hex, const char *ct_hex) {
    uint8_t key[32], pt[16], expected[16], got[16], back[16];
    size_t klen = unhex(key_hex, key);
    size_t blen = unhex(pt_hex, pt);
    CHECK(unhex(ct_hex, expected) == blen);
    sc_ctx ctx;
    sc_status rc = sc_init(&ctx, alg, backend, key, klen);
    CHECK(rc == SC_OK);
    if (rc != SC_OK) return;
    CHECK(sc_block_size(&ctx) == blen);
    CHECK(sc_encrypt_block(&ctx, pt, got) == SC_OK);
    if (memcmp(got, expected, blen) != 0) {
        fprintf(stderr, "KAT mismatch: %s/%s got=",
                sc_algorithm_name(alg), sc_backend_name(backend));
        for (size_t i = 0; i < blen; ++i) fprintf(stderr, "%02x", got[i]);
        fputc('\n', stderr);
    }
    CHECK(memcmp(got, expected, blen) == 0);
    CHECK(sc_decrypt_block(&ctx, got, back) == SC_OK);
    CHECK(memcmp(back, pt, blen) == 0);
    memcpy(back, pt, blen);
    CHECK(sc_encrypt_block(&ctx, back, back) == SC_OK);
    CHECK(memcmp(back, expected, blen) == 0);
}

static void test_kats(void) {
    const char *pt = "00112233445566778899aabbccddeeff";
    kat(SC_AES_128, SC_BACKEND_REF, "000102030405060708090a0b0c0d0e0f",
        pt, "69c4e0d86a7b0430d8cdb78070b4c55a");
    kat(SC_AES_192, SC_BACKEND_REF,
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        pt, "dda97ca4864cdfe06eaf70a0ec0d7191");
    kat(SC_AES_256, SC_BACKEND_REF,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        pt, "8ea2b7ca516745bfeafc49904b496089");
    kat(SC_AES_128, SC_BACKEND_TTABLE, "000102030405060708090a0b0c0d0e0f",
        pt, "69c4e0d86a7b0430d8cdb78070b4c55a");
    kat(SC_AES_128, SC_BACKEND_AUTO, "000102030405060708090a0b0c0d0e0f",
        pt, "69c4e0d86a7b0430d8cdb78070b4c55a");
    kat(SC_SM4_128, SC_BACKEND_REF, "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "681edf34d206965e86b3e94f536e4246");
    kat(SC_SM4_128, SC_BACKEND_TTABLE, "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "681edf34d206965e86b3e94f536e4246");
    kat(SC_SM4_128, SC_BACKEND_TTABLE_1K, "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "681edf34d206965e86b3e94f536e4246");
    kat(SC_SM4_128, SC_BACKEND_TTABLE_2K, "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "681edf34d206965e86b3e94f536e4246");
    kat(SC_SM4_128, SC_BACKEND_SHUFFLE, "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "681edf34d206965e86b3e94f536e4246");
    kat(SC_SM4_128, SC_BACKEND_AES_HW, "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "681edf34d206965e86b3e94f536e4246");
    kat(SC_GIFT64_128, SC_BACKEND_REF,
        "00000000000000000000000000000000",
        "0000000000000000", "f62bc3ef34f775ac");
    kat(SC_TWINE_80, SC_BACKEND_REF, "00112233445566778899",
        "0123456789abcdef", "7c1f0f80b1df9c28");
    kat(SC_TWINE_80, SC_BACKEND_SHUFFLE, "00112233445566778899",
        "0123456789abcdef", "7c1f0f80b1df9c28");
    kat(SC_TWINE_128, SC_BACKEND_REF,
        "00112233445566778899aabbccddeeff",
        "0123456789abcdef", "979ff9b379b5a9b8");
}

static void test_ctr(void) {
    uint8_t key[16], counter[16], pt[16], ct[16], expected[16], back[16];
    unhex("2b7e151628aed2a6abf7158809cf4f3c", key);
    unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", counter);
    unhex("6bc1bee22e409f96e93d7e117393172a", pt);
    unhex("874d6191b620e3261bef6864990db6ce", expected);
    sc_ctx ctx;
    CHECK(sc_init(&ctx, SC_AES_128, SC_BACKEND_REF, key, 16) == SC_OK);
    uint8_t initial[16];
    memcpy(initial, counter, 16);
    CHECK(sc_ctr_xor(&ctx, counter, pt, ct, sizeof(pt)) == SC_OK);
    CHECK(memcmp(ct, expected, 16) == 0);
    memcpy(counter, initial, 16);
    CHECK(sc_ctr_xor(&ctx, counter, ct, back, sizeof(back)) == SC_OK);
    CHECK(memcmp(back, pt, 16) == 0);

    memset(counter, 0xff, 16);
    CHECK(sc_ctr_xor(&ctx, counter, pt, ct, 1) == SC_ERR_COUNTER_WRAP);
}

static void test_gcm(void) {
    uint8_t key[16] = {0}, iv[12] = {0}, pt[16] = {0};
    uint8_t ct[16], tag[16], expected_ct[16], expected_tag[16], back[16];
    unhex("0388dace60b6a392f328c2b971b2fe78", expected_ct);
    unhex("ab6e47d42cec13bdf53a67b21257bddf", expected_tag);
    sc_ctx ctx;
    CHECK(sc_init(&ctx, SC_AES_128, SC_BACKEND_REF, key, 16) == SC_OK);
    CHECK(sc_gcm_encrypt(&ctx, iv, sizeof(iv), NULL, 0, pt, ct, sizeof(pt),
                         tag, sizeof(tag)) == SC_OK);
    CHECK(memcmp(ct, expected_ct, 16) == 0);
    CHECK(memcmp(tag, expected_tag, 16) == 0);
    CHECK(sc_gcm_decrypt(&ctx, iv, sizeof(iv), NULL, 0, ct, back, sizeof(ct),
                         tag, sizeof(tag)) == SC_OK);
    CHECK(memcmp(back, pt, 16) == 0);
    tag[0] ^= 1;
    memset(back, 0xaa, 16);
    CHECK(sc_gcm_decrypt(&ctx, iv, sizeof(iv), NULL, 0, ct, back, sizeof(ct),
                         tag, sizeof(tag)) == SC_ERR_AUTH);
    uint8_t zero[16] = {0};
    CHECK(memcmp(back, zero, 16) == 0);

    uint8_t sm4_key[16], sm4_iv[12], sm4_aad[20], sm4_pt[64];
    uint8_t sm4_ct[64], sm4_expected[64], sm4_tag[16], sm4_expected_tag[16];
    unhex("0123456789abcdeffedcba9876543210", sm4_key);
    unhex("00001234567800000000abcd", sm4_iv);
    unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", sm4_aad);
    unhex("aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd"
          "eeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa", sm4_pt);
    unhex("17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735"
          "d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d",
          sm4_expected);
    unhex("83de3541e4c2b58177e065a9bf7b62ec", sm4_expected_tag);
    CHECK(sc_init(&ctx, SC_SM4_128, SC_BACKEND_REF, sm4_key, 16) == SC_OK);
    CHECK(sc_gcm_encrypt(&ctx, sm4_iv, sizeof(sm4_iv), sm4_aad, sizeof(sm4_aad),
                         sm4_pt, sm4_ct, sizeof(sm4_pt), sm4_tag, 16) == SC_OK);
    CHECK(memcmp(sm4_ct, sm4_expected, sizeof(sm4_ct)) == 0);
    CHECK(memcmp(sm4_tag, sm4_expected_tag, 16) == 0);
}

static void test_xts_roundtrip(void) {
    uint8_t k1[16], k2[16], tweak[16], pt[63], ct[63], back[63];
    for (size_t i = 0; i < 16; ++i) {
        k1[i] = (uint8_t)i;
        k2[i] = (uint8_t)(0xf0U + i);
        tweak[i] = (uint8_t)(3U * i);
    }
    for (size_t i = 0; i < sizeof(pt); ++i) pt[i] = (uint8_t)(i * 7U + 1U);
    sc_ctx data, tw;
    CHECK(sc_init(&data, SC_AES_128, SC_BACKEND_REF, k1, 16) == SC_OK);
    CHECK(sc_init(&tw, SC_AES_128, SC_BACKEND_REF, k2, 16) == SC_OK);
    CHECK(sc_xts_encrypt(&data, &tw, tweak, pt, ct, sizeof(pt), SC_XTS_IEEE_LE) == SC_OK);
    CHECK(sc_xts_decrypt(&data, &tw, tweak, ct, back, sizeof(pt), SC_XTS_IEEE_LE) == SC_OK);
    CHECK(memcmp(pt, back, sizeof(pt)) == 0);
    CHECK(sc_xts_encrypt(&data, &tw, tweak, pt, ct, 15, SC_XTS_IEEE_LE) == SC_ERR_DATA_UNIT);

    uint8_t sm4k1[16], sm4k2[16];
    for (size_t i = 0; i < 16; ++i) {
        sm4k1[i] = (uint8_t)(0x55U + i);
        sm4k2[i] = (uint8_t)(0xa0U - i);
    }
    CHECK(sc_init(&data, SC_SM4_128, SC_BACKEND_REF, sm4k1, 16) == SC_OK);
    CHECK(sc_init(&tw, SC_SM4_128, SC_BACKEND_REF, sm4k2, 16) == SC_OK);
    CHECK(sc_xts_encrypt(&data, &tw, tweak, pt, ct, sizeof(pt), SC_XTS_GBT_BE) == SC_OK);
    CHECK(sc_xts_decrypt(&data, &tw, tweak, ct, back, sizeof(pt), SC_XTS_GBT_BE) == SC_OK);
    CHECK(memcmp(pt, back, sizeof(pt)) == 0);
    CHECK(sc_xts_encrypt(&data, &tw, tweak, pt, ct, sizeof(pt), SC_XTS_IEEE_LE) == SC_OK);
    CHECK(sc_xts_decrypt(&data, &tw, tweak, ct, back, sizeof(pt), SC_XTS_IEEE_LE) == SC_OK);
    CHECK(memcmp(pt, back, sizeof(pt)) == 0);
}

static void test_random_cross(void) {
    uint32_t x = 0x243f6a88U;
    uint8_t key[16], pt[16], a[16], b[16];
    for (size_t n = 0; n < 200; ++n) {
        for (size_t i = 0; i < 16; ++i) {
            x = x * 1664525U + 1013904223U;
            key[i] = (uint8_t)(x >> 24);
            x = x * 1664525U + 1013904223U;
            pt[i] = (uint8_t)(x >> 24);
        }
        sc_ctx ref, opt;
        CHECK(sc_init(&ref, SC_SM4_128, SC_BACKEND_REF, key, 16) == SC_OK);
        CHECK(sc_init(&opt, SC_SM4_128, SC_BACKEND_TTABLE_2K, key, 16) == SC_OK);
        CHECK(sc_encrypt_block(&ref, pt, a) == SC_OK);
        CHECK(sc_encrypt_block(&opt, pt, b) == SC_OK);
        CHECK(memcmp(a, b, 16) == 0);
    }
}

static void test_gfni_model(void) {
    static const uint8_t sm4_sbox[256] = {
        0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
        0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
        0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
        0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
        0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
        0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
        0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
        0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
        0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
        0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
        0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
        0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
        0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
        0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
        0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
        0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
    };
    for (unsigned x = 0; x < 256; ++x)
        CHECK(sc_sm4_gfni_scalar_model((uint8_t)x) == sm4_sbox[x]);
}

static size_t key_len_for(sc_algorithm alg) {
    if (alg == SC_AES_192) return 24;
    if (alg == SC_AES_256) return 32;
    if (alg == SC_TWINE_80) return 10;
    return 16;
}

static void test_multiblock_backends(void) {
    static const struct {
        sc_algorithm alg;
        sc_backend backend;
    } cases[] = {
        {SC_AES_128, SC_BACKEND_TTABLE},
        {SC_AES_192, SC_BACKEND_TTABLE},
        {SC_AES_256, SC_BACKEND_TTABLE},
        {SC_AES_128, SC_BACKEND_AES_HW},
        {SC_AES_192, SC_BACKEND_AES_HW},
        {SC_AES_256, SC_BACKEND_AES_HW},
        {SC_SM4_128, SC_BACKEND_TTABLE},
        {SC_SM4_128, SC_BACKEND_TTABLE_1K},
        {SC_SM4_128, SC_BACKEND_TTABLE_2K},
        {SC_SM4_128, SC_BACKEND_SHUFFLE},
        {SC_SM4_128, SC_BACKEND_AES_HW},
        {SC_SM4_128, SC_BACKEND_GFNI},
        {SC_SM4_128, SC_BACKEND_SM4_HW},
        {SC_GIFT64_128, SC_BACKEND_REF},
        {SC_GIFT64_128, SC_BACKEND_SHUFFLE},
        {SC_TWINE_80, SC_BACKEND_SHUFFLE},
        {SC_TWINE_128, SC_BACKEND_SHUFFLE}
    };
    static const size_t block_counts[] = {0,1,3,4,7,8,9,15,16,17};
    uint8_t key[32], storage[2][17 * 16 + 2];
    uint8_t expected[17 * 16], recovered[17 * 16];
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
        size_t klen = key_len_for(cases[c].alg);
        for (size_t i = 0; i < klen; ++i) key[i] = (uint8_t)(17U * i + c);
        sc_ctx ref, opt;
        CHECK(sc_init(&ref, cases[c].alg, SC_BACKEND_REF, key, klen) == SC_OK);
        sc_status init = sc_init(&opt, cases[c].alg, cases[c].backend, key, klen);
        if (init == SC_ERR_UNSUPPORTED) continue;
        CHECK(init == SC_OK);
        size_t bs = sc_block_size(&ref);
        for (size_t n = 0; n < sizeof(block_counts) / sizeof(block_counts[0]); ++n) {
            size_t blocks = block_counts[n], bytes = bs * blocks;
            uint8_t *input = storage[0] + 1;
            uint8_t *actual = storage[1] + 1;
            for (size_t i = 0; i < bytes; ++i)
                input[i] = (uint8_t)(i * 29U + c + blocks);
            CHECK(sc_encrypt_blocks(&ref, input, expected, blocks) == SC_OK);
            CHECK(sc_encrypt_blocks(&opt, input, actual, blocks) == SC_OK);
            CHECK(memcmp(expected, actual, bytes) == 0);
            CHECK(sc_decrypt_blocks(&opt, actual, recovered, blocks) == SC_OK);
            CHECK(memcmp(input, recovered, bytes) == 0);
            memcpy(actual, input, bytes);
            CHECK(sc_encrypt_blocks(&opt, actual, actual, blocks) == SC_OK);
            CHECK(sc_decrypt_blocks(&opt, actual, actual, blocks) == SC_OK);
            CHECK(memcmp(input, actual, bytes) == 0);
        }
    }
}

static void test_mode_boundaries(void) {
    uint8_t key[16] = {0}, input[80], output[80], before[80];
    uint8_t counter[16], counter_before[16], tweak[16];
    for (size_t i = 0; i < sizeof(input); ++i) input[i] = (uint8_t)(i * 11U);
    sc_ctx aes, tw;
    CHECK(sc_init(&aes, SC_AES_128, SC_BACKEND_AUTO, key, 16) == SC_OK);
    key[0] = 1;
    CHECK(sc_init(&tw, SC_AES_128, SC_BACKEND_AUTO, key, 16) == SC_OK);
    memset(counter, 0xff, sizeof(counter));
    memset(output, 0xa5, sizeof(output));
    memcpy(before, output, sizeof(output));
    memcpy(counter_before, counter, sizeof(counter));
    CHECK(sc_ctr_xor(&aes, counter, input, output, 1) == SC_ERR_COUNTER_WRAP);
    CHECK(memcmp(output, before, sizeof(output)) == 0);
    CHECK(memcmp(counter, counter_before, sizeof(counter)) == 0);
    for (size_t len = 17; len <= 63; len += (len == 17 ? 14 : 32)) {
        CHECK(sc_xts_tweak_from_data_unit(0x0102030405060708ULL,
                                          SC_XTS_IEEE_LE, tweak) == SC_OK);
        memcpy(output, input, len);
        CHECK(sc_xts_encrypt(&aes, &tw, tweak, output, output, len,
                             SC_XTS_IEEE_LE) == SC_OK);
        CHECK(sc_xts_decrypt(&aes, &tw, tweak, output, output, len,
                             SC_XTS_IEEE_LE) == SC_OK);
        CHECK(memcmp(output, input, len) == 0);
    }
    CHECK(sc_xts_tweak_from_data_unit(1, (sc_xts_convention)99, tweak) ==
          SC_ERR_ARGUMENT);
    CHECK(sc_xts_encrypt(&aes, &tw, tweak, input, output, 16,
                         (sc_xts_convention)99) == SC_ERR_ARGUMENT);
}

int main(void) {
    test_kats();
    test_ctr();
    test_gcm();
    test_xts_roundtrip();
    test_random_cross();
    test_gfni_model();
    test_multiblock_backends();
    test_mode_boundaries();
    if (tests_failed) {
        fprintf(stderr, "%u/%u checks failed\n", tests_failed, tests_run);
        return 1;
    }
    printf("PASS: %u checks\n", tests_run);
    sc_cpu_features f = sc_detect_cpu_features();
    printf("features: arm-aes=%d arm-pmull=%d arm-sm4=%d "
           "x86-aesni=%d x86-ssse3=%d x86-avx2=%d x86-vaes=%d "
           "x86-pclmul=%d x86-vpclmul=%d x86-gfni=%d x86-sm4=%d\n",
           f.arm_aes, f.arm_pmull, f.arm_sm4, f.x86_aesni, f.x86_ssse3,
           f.x86_avx2, f.x86_vaes, f.x86_pclmul, f.x86_vpclmul,
           f.x86_gfni, f.x86_sm4);
    return 0;
}
