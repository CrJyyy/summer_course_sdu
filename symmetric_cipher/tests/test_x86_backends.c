#include "../src/internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned tests_run;
static unsigned tests_failed;

#define CHECK(cond) do { \
    ++tests_run; \
    if (!(cond)) { \
        ++tests_failed; \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    } \
} while (0)

static uint32_t prng_state = UINT32_C(0x6a09e667);

static void random_bytes(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        prng_state ^= prng_state << 13;
        prng_state ^= prng_state >> 17;
        prng_state ^= prng_state << 5;
        out[i] = (uint8_t)(prng_state >> 24);
    }
}

static size_t key_len_for(sc_algorithm algorithm) {
    if (algorithm == SC_AES_192) return 24;
    if (algorithm == SC_AES_256) return 32;
    if (algorithm == SC_TWINE_80) return 10;
    return 16;
}

static sc_sm4_key reverse_sm4_key(const sc_sm4_key *key) {
    sc_sm4_key reversed;
    for (size_t i = 0; i < 32; ++i) reversed.rk[i] = key->rk[31U - i];
    return reversed;
}

static void test_dispatch(const sc_cpu_features *features) {
    static const struct {
        sc_algorithm algorithm;
        sc_backend backend;
        int available;
    } fixed[] = {
        {SC_AES_128, SC_BACKEND_AES_HW, 0},
        {SC_SM4_128, SC_BACKEND_SHUFFLE, 0},
        {SC_SM4_128, SC_BACKEND_AES_HW, 0},
        {SC_SM4_128, SC_BACKEND_GFNI, 0},
        {SC_SM4_128, SC_BACKEND_SM4_HW, 0}
    };
    uint8_t key[32] = {0};
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); ++i) {
        int available = fixed[i].available;
        if (fixed[i].backend == SC_BACKEND_AES_HW &&
            fixed[i].algorithm == SC_AES_128)
            available = features->x86_aesni;
        else if (fixed[i].backend == SC_BACKEND_SHUFFLE)
            available = features->x86_ssse3;
        else if (fixed[i].backend == SC_BACKEND_AES_HW)
            available = features->x86_aesni && features->x86_ssse3;
        else if (fixed[i].backend == SC_BACKEND_GFNI)
            available = features->x86_gfni;
        else if (fixed[i].backend == SC_BACKEND_SM4_HW)
            available = features->x86_sm4;
        sc_ctx ctx;
        sc_status rc = sc_init(&ctx, fixed[i].algorithm, fixed[i].backend,
                               key, key_len_for(fixed[i].algorithm));
        CHECK(rc == (available ? SC_OK : SC_ERR_UNSUPPORTED));
        if (rc == SC_OK) CHECK(sc_backend_id(&ctx) == fixed[i].backend);
    }

    sc_ctx auto_ctx;
    CHECK(sc_init(&auto_ctx, SC_AES_128, SC_BACKEND_AUTO, key, 16) == SC_OK);
    CHECK(sc_backend_id(&auto_ctx) ==
          (features->x86_aesni ? SC_BACKEND_AES_HW : SC_BACKEND_REF));
    CHECK(sc_init(&auto_ctx, SC_SM4_128, SC_BACKEND_AUTO, key, 16) == SC_OK);
    sc_backend expected = SC_BACKEND_REF;
    if (features->x86_sm4)
        expected = SC_BACKEND_SM4_HW;
    else if (features->x86_aesni && features->x86_ssse3)
        expected = SC_BACKEND_AES_HW;
    CHECK(sc_backend_id(&auto_ctx) == expected);
}

static void test_aes_direct(const sc_cpu_features *features) {
    if (!features->x86_aesni) return;
    static const sc_algorithm algorithms[] =
        {SC_AES_128, SC_AES_192, SC_AES_256};
    for (size_t a = 0; a < sizeof(algorithms) / sizeof(algorithms[0]); ++a) {
        uint8_t key[32], input[128], expected[128], got[128], recovered[128];
        random_bytes(key, key_len_for(algorithms[a]));
        random_bytes(input, sizeof(input));
        sc_ctx ctx;
        CHECK(sc_init(&ctx, algorithms[a], SC_BACKEND_REF, key,
                      key_len_for(algorithms[a])) == SC_OK);
        const sc_aes_key *expanded = &sc_const(&ctx)->key.aes;
        CHECK(sc_encrypt_blocks(&ctx, input, expected, 8) == SC_OK);

        sc_arm_aes_encrypt(expanded, input, got);
        CHECK(memcmp(got, expected, 16) == 0);
        sc_arm_aes_decrypt(expanded, expected, recovered);
        CHECK(memcmp(recovered, input, 16) == 0);

        sc_arm_aes_encrypt4(expanded, input, got);
        CHECK(memcmp(got, expected, 64) == 0);
        sc_arm_aes_decrypt4(expanded, expected, recovered);
        CHECK(memcmp(recovered, input, 64) == 0);

        if (features->x86_vaes && features->x86_avx2) {
            sc_x86_aes_encrypt8_vaes(expanded, input, got);
            CHECK(memcmp(got, expected, 128) == 0);
            sc_x86_aes_decrypt8_vaes(expanded, expected, recovered);
            CHECK(memcmp(recovered, input, 128) == 0);
        }
    }
}

static void test_sm4_direct(const sc_cpu_features *features) {
    uint8_t key[16], input[128], expected[128], got[128], recovered[128];
    random_bytes(key, sizeof(key));
    random_bytes(input, sizeof(input));
    sc_ctx ctx;
    CHECK(sc_init(&ctx, SC_SM4_128, SC_BACKEND_REF, key, sizeof(key)) == SC_OK);
    CHECK(sc_encrypt_blocks(&ctx, input, expected, 8) == SC_OK);
    const sc_sm4_key *expanded = &sc_const(&ctx)->key.sm4;
    sc_sm4_key reversed = reverse_sm4_key(expanded);

    if (features->x86_ssse3) {
        sc_x86_sm4_encrypt4_shuffle(expanded, input, got);
        CHECK(memcmp(got, expected, 64) == 0);
        sc_x86_sm4_encrypt4_shuffle(&reversed, expected, recovered);
        CHECK(memcmp(recovered, input, 64) == 0);
    }
    if (features->x86_aesni && features->x86_ssse3) {
        sc_sm4_encrypt4_aes_assist(expanded, input, got);
        CHECK(memcmp(got, expected, 64) == 0);
        sc_sm4_encrypt4_aes_assist(&reversed, expected, recovered);
        CHECK(memcmp(recovered, input, 64) == 0);
    }
    if (features->x86_gfni) {
        for (unsigned x = 0; x < 256; ++x)
            CHECK(sc_x86_sm4_gfni_sbox_byte((uint8_t)x) ==
                  sc_sm4_sbox_byte((uint8_t)x));
        sc_x86_sm4_encrypt_gfni(expanded, input, got);
        CHECK(memcmp(got, expected, 16) == 0);
        sc_x86_sm4_encrypt_gfni(&reversed, expected, recovered);
        CHECK(memcmp(recovered, input, 16) == 0);
        sc_x86_sm4_encrypt4_gfni(expanded, input, got);
        CHECK(memcmp(got, expected, 64) == 0);
        sc_x86_sm4_encrypt4_gfni(&reversed, expected, recovered);
        CHECK(memcmp(recovered, input, 64) == 0);
    }
    if (features->x86_sm4) {
        sc_x86_sm4_encrypt8_hw(expanded, input, got);
        CHECK(memcmp(got, expected, 128) == 0);
        sc_x86_sm4_encrypt8_hw(&reversed, expected, recovered);
        CHECK(memcmp(recovered, input, 128) == 0);
    }
}

static void test_twine_direct(const sc_cpu_features *features) {
    if (!features->x86_ssse3) return;
    static const sc_algorithm algorithms[] = {SC_TWINE_80, SC_TWINE_128};
    for (size_t a = 0; a < sizeof(algorithms) / sizeof(algorithms[0]); ++a) {
        uint8_t key[16], input[32], expected[32], got[32], recovered[32];
        random_bytes(key, key_len_for(algorithms[a]));
        random_bytes(input, sizeof(input));
        sc_ctx ctx;
        CHECK(sc_init(&ctx, algorithms[a], SC_BACKEND_REF, key,
                      key_len_for(algorithms[a])) == SC_OK);
        CHECK(sc_encrypt_blocks(&ctx, input, expected, 4) == SC_OK);
        const sc_twine_key *expanded = &sc_const(&ctx)->key.twine;
        sc_x86_twine_crypt4_shuffle(expanded, input, got, 0);
        CHECK(memcmp(got, expected, sizeof(got)) == 0);
        sc_x86_twine_crypt4_shuffle(expanded, expected, recovered, 1);
        CHECK(memcmp(recovered, input, sizeof(recovered)) == 0);
    }
}

static void shift_right_one(uint8_t value[16]) {
    uint8_t carry = 0;
    for (size_t i = 0; i < 16; ++i) {
        uint8_t next = (uint8_t)(value[i] & 1U);
        value[i] = (uint8_t)((value[i] >> 1) | (carry << 7));
        carry = next;
    }
}

static void ghash_scalar(uint8_t x[16], const uint8_t h[16]) {
    uint8_t z[16] = {0}, v[16];
    memcpy(v, h, 16);
    for (size_t bit_no = 0; bit_no < 128; ++bit_no) {
        uint8_t bit =
            (uint8_t)((x[bit_no / 8] >> (7U - (bit_no & 7U))) & 1U);
        uint8_t mask = (uint8_t)(0U - bit);
        for (size_t i = 0; i < 16; ++i) z[i] ^= (uint8_t)(v[i] & mask);
        uint8_t lsb = (uint8_t)(v[15] & 1U);
        shift_right_one(v);
        v[0] ^= (uint8_t)(0xe1U & (uint8_t)(0U - lsb));
    }
    memcpy(x, z, 16);
}

static void test_ghash_direct(const sc_cpu_features *features) {
    for (size_t sample = 0; sample < 128; ++sample) {
        uint8_t x[16], h[16], expected[16], got[16];
        random_bytes(x, sizeof(x));
        random_bytes(h, sizeof(h));
        memcpy(expected, x, sizeof(x));
        ghash_scalar(expected, h);
        if (features->x86_pclmul) {
            memcpy(got, x, sizeof(x));
            CHECK(sc_x86_ghash_mul_pclmul(got, h) == 1);
            CHECK(memcmp(got, expected, sizeof(got)) == 0);
        }
        if (features->x86_vpclmul && features->x86_avx2) {
            memcpy(got, x, sizeof(x));
            CHECK(sc_x86_ghash_mul_vpclmul(got, h) == 1);
            CHECK(memcmp(got, expected, sizeof(got)) == 0);
        }
    }
}

static void require_modern_features(const sc_cpu_features *features) {
    const char *required = getenv("SC_REQUIRE_MODERN_X86");
    if (required == NULL || strcmp(required, "1") != 0) return;
    CHECK(features->x86_aesni);
    CHECK(features->x86_ssse3);
    CHECK(features->x86_avx2);
    CHECK(features->x86_vaes);
    CHECK(features->x86_pclmul);
    CHECK(features->x86_vpclmul);
    CHECK(features->x86_gfni);
}

static void print_isa(const char *name, int available) {
    printf("ISA %s %s\n", name, available ? "pass" : "unsupported");
}

int main(void) {
#if !defined(__x86_64__) && !defined(__i386__)
    puts("SKIP: test_x86_backends requires an x86 target");
    return 0;
#else
    sc_cpu_features features = sc_detect_cpu_features();
    require_modern_features(&features);
    test_dispatch(&features);
    test_aes_direct(&features);
    test_sm4_direct(&features);
    test_twine_direct(&features);
    test_ghash_direct(&features);

    print_isa("aesni", features.x86_aesni);
    print_isa("ssse3", features.x86_ssse3);
    print_isa("avx2", features.x86_avx2);
    print_isa("vaes", features.x86_vaes && features.x86_avx2);
    print_isa("pclmul", features.x86_pclmul);
    print_isa("vpclmul", features.x86_vpclmul && features.x86_avx2);
    print_isa("gfni", features.x86_gfni);
    print_isa("vsm4", features.x86_sm4);
    if (tests_failed) {
        fprintf(stderr, "%u/%u x86 checks failed\n", tests_failed, tests_run);
        return 1;
    }
    printf("PASS: %u x86 checks\n", tests_run);
    return 0;
#endif
}
