#ifndef SYMCRYPTO_H
#define SYMCRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SC_OK = 0,
    SC_ERR_ARGUMENT = -1,
    SC_ERR_KEY_SIZE = -2,
    SC_ERR_UNSUPPORTED = -3,
    SC_ERR_COUNTER_WRAP = -4,
    SC_ERR_AUTH = -5,
    SC_ERR_DATA_UNIT = -6
} sc_status;

typedef enum {
    SC_AES_128,
    SC_AES_192,
    SC_AES_256,
    SC_SM4_128,
    SC_GIFT64_128,
    SC_TWINE_80,
    SC_TWINE_128
} sc_algorithm;

typedef enum {
    SC_BACKEND_AUTO,
    SC_BACKEND_REF,
    SC_BACKEND_TTABLE,
    SC_BACKEND_TTABLE_1K,
    SC_BACKEND_TTABLE_2K,
    SC_BACKEND_SHUFFLE,
    SC_BACKEND_AES_HW,
    SC_BACKEND_GFNI,
    SC_BACKEND_SM4_HW
} sc_backend;

typedef enum {
    SC_XTS_IEEE_LE,
    SC_XTS_GBT_BE
} sc_xts_convention;

/*
 * Fixed-size ABI object.  Its representation is deliberately opaque so that
 * callers do not depend on expanded-key layouts.
 */
typedef struct {
    uint64_t opaque[256];
} sc_ctx;

typedef struct {
    int arm_aes;
    int arm_pmull;
    int arm_sm4;
    int x86_aesni;
    int x86_ssse3;
    int x86_avx2;
    int x86_vaes;
    int x86_pclmul;
    int x86_vpclmul;
    int x86_gfni;
    int x86_sm4;
} sc_cpu_features;

sc_status sc_init(sc_ctx *ctx, sc_algorithm algorithm, sc_backend requested,
                  const uint8_t *key, size_t key_len);
sc_status sc_encrypt_block(const sc_ctx *ctx, const uint8_t *in, uint8_t *out);
sc_status sc_decrypt_block(const sc_ctx *ctx, const uint8_t *in, uint8_t *out);
sc_status sc_encrypt_blocks(const sc_ctx *ctx, const uint8_t *in, uint8_t *out,
                            size_t blocks);
sc_status sc_decrypt_blocks(const sc_ctx *ctx, const uint8_t *in, uint8_t *out,
                            size_t blocks);
size_t sc_block_size(const sc_ctx *ctx);
sc_algorithm sc_algorithm_id(const sc_ctx *ctx);
sc_backend sc_backend_id(const sc_ctx *ctx);
const char *sc_algorithm_name(sc_algorithm algorithm);
const char *sc_backend_name(sc_backend backend);
sc_cpu_features sc_detect_cpu_features(void);

sc_status sc_ctr_xor(const sc_ctx *ctx, uint8_t *counter, const uint8_t *in,
                     uint8_t *out, size_t len);

sc_status sc_gcm_encrypt(const sc_ctx *ctx, const uint8_t *iv, size_t iv_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, uint8_t *ciphertext,
                         size_t len, uint8_t *tag, size_t tag_len);
sc_status sc_gcm_decrypt(const sc_ctx *ctx, const uint8_t *iv, size_t iv_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, uint8_t *plaintext,
                         size_t len, const uint8_t *tag, size_t tag_len);

sc_status sc_xts_encrypt(const sc_ctx *data_ctx, const sc_ctx *tweak_ctx,
                         const uint8_t tweak[16], const uint8_t *plaintext,
                         uint8_t *ciphertext, size_t len,
                         sc_xts_convention convention);
sc_status sc_xts_decrypt(const sc_ctx *data_ctx, const sc_ctx *tweak_ctx,
                         const uint8_t tweak[16], const uint8_t *ciphertext,
                         uint8_t *plaintext, size_t len,
                         sc_xts_convention convention);
sc_status sc_xts_tweak_from_data_unit(uint64_t data_unit_no,
                                      sc_xts_convention convention,
                                      uint8_t tweak[16]);

#ifdef __cplusplus
}
#endif

#endif
