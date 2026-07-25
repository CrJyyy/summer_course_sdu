#include "symcrypto.h"

#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t prng_state = 0x9e3779b9U;
static unsigned checks;

static void random_bytes(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        prng_state ^= prng_state << 13;
        prng_state ^= prng_state >> 17;
        prng_state ^= prng_state << 5;
        p[i] = (uint8_t)(prng_state >> 24);
    }
}

static void require(int ok, const char *what) {
    ++checks;
    if (!ok) {
        fprintf(stderr, "OpenSSL differential FAIL: %s\n", what);
        exit(1);
    }
}

static void openssl_encrypt(const char *name, const uint8_t *key,
                            const uint8_t *iv, const uint8_t *in,
                            size_t len, uint8_t *out) {
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, tail = 0;
    require(cipher != NULL && ctx != NULL, "fetch cipher");
    require(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) == 1, "encrypt init");
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    require(EVP_EncryptUpdate(ctx, out, &n, in, (int)len) == 1, "encrypt update");
    require(EVP_EncryptFinal_ex(ctx, out + n, &tail) == 1, "encrypt final");
    require((size_t)(n + tail) == len, "encrypt length");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
}

static void openssl_gcm(const char *name, const uint8_t key[16],
                        const uint8_t *iv, size_t iv_len, const uint8_t *aad,
                        size_t aad_len, const uint8_t *in, size_t len,
                        uint8_t *out, uint8_t tag[16]) {
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, total = 0;
    require(cipher != NULL && ctx != NULL, "fetch GCM");
    require(EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL) == 1, "GCM init");
    require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv_len, NULL) == 1,
            "GCM IV length");
    require(EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL) == 1, "GCM key/IV");
    require(EVP_EncryptUpdate(ctx, NULL, &n, aad, (int)aad_len) == 1, "GCM AAD");
    require(EVP_EncryptUpdate(ctx, out, &n, in, (int)len) == 1, "GCM data");
    total = n;
    require(EVP_EncryptFinal_ex(ctx, out + total, &n) == 1, "GCM final");
    total += n;
    require((size_t)total == len, "GCM length");
    require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1,
            "GCM tag");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
}

static void test_algorithm(sc_algorithm algorithm, const char *ecb,
                           const char *ctr, const char *gcm,
                           const char *xts) {
    for (unsigned iter = 0; iter < 40; ++iter) {
        uint8_t key[16], key2[16], combined[32], iv[16], tweak[16];
        uint8_t in[97], ours[97], theirs[97], tag1[16], tag2[16];
        random_bytes(key, sizeof(key));
        random_bytes(key2, sizeof(key2));
        random_bytes(iv, sizeof(iv));
        random_bytes(tweak, sizeof(tweak));
        random_bytes(in, sizeof(in));
        sc_ctx ctx, tw;
        require(sc_init(&ctx, algorithm, SC_BACKEND_REF, key, 16) == SC_OK,
                "local init");
        require(sc_init(&tw, algorithm, SC_BACKEND_REF, key2, 16) == SC_OK,
                "local tweak init");

        require(sc_encrypt_block(&ctx, in, ours) == SC_OK, "local ECB");
        openssl_encrypt(ecb, key, NULL, in, 16, theirs);
        require(memcmp(ours, theirs, 16) == 0, "ECB mismatch");

        uint8_t counter[16];
        memcpy(counter, iv, 16);
        require(sc_ctr_xor(&ctx, counter, in, ours, sizeof(in)) == SC_OK,
                "local CTR");
        openssl_encrypt(ctr, key, iv, in, sizeof(in), theirs);
        require(memcmp(ours, theirs, sizeof(in)) == 0, "CTR mismatch");

        size_t iv_len = (iter & 1U) ? 12U : 16U;
        require(sc_gcm_encrypt(&ctx, iv, iv_len, in, 13, in, ours, sizeof(in),
                               tag1, sizeof(tag1)) == SC_OK, "local GCM");
        openssl_gcm(gcm, key, iv, iv_len, in, 13, in, sizeof(in), theirs, tag2);
        require(memcmp(ours, theirs, sizeof(in)) == 0, "GCM data mismatch");
        require(memcmp(tag1, tag2, sizeof(tag1)) == 0, "GCM tag mismatch");

        memcpy(combined, key, 16);
        memcpy(combined + 16, key2, 16);
        require(sc_xts_encrypt(&ctx, &tw, tweak, in, ours, 64,
                               algorithm == SC_SM4_128 ? SC_XTS_GBT_BE :
                               SC_XTS_IEEE_LE) == SC_OK, "local XTS");
        openssl_encrypt(xts, combined, tweak, in, 64, theirs);
        if (memcmp(ours, theirs, 64) != 0) {
            size_t q = 0;
            while (q < 64 && ours[q] == theirs[q]) ++q;
            fprintf(stderr, "%s XTS first mismatch at byte %zu\n", xts, q);
        }
        require(memcmp(ours, theirs, 64) == 0, "XTS mismatch");
        require(sc_xts_encrypt(&ctx, &tw, tweak, in, ours, 63,
                               algorithm == SC_SM4_128 ? SC_XTS_GBT_BE :
                               SC_XTS_IEEE_LE) == SC_OK, "local XTS CTS");
        openssl_encrypt(xts, combined, tweak, in, 63, theirs);
        require(memcmp(ours, theirs, 63) == 0, "XTS CTS mismatch");
    }
}

int main(void) {
    test_algorithm(SC_AES_128, "AES-128-ECB", "AES-128-CTR",
                   "AES-128-GCM", "AES-128-XTS");
    test_algorithm(SC_SM4_128, "SM4-ECB", "SM4-CTR",
                   "SM4-GCM", "SM4-XTS");
    printf("PASS: %u OpenSSL 3.6 differential checks (%s)\n",
           checks, OpenSSL_version(OPENSSL_VERSION));
    return 0;
}
