#ifndef SYMCRYPTO_INTERNAL_H
#define SYMCRYPTO_INTERNAL_H

#include "symcrypto.h"

#include <stdint.h>
#include <string.h>

#define SC_MAGIC UINT32_C(0x53434331)
#define SC_MAX_BLOCK 16U

typedef struct {
    uint8_t round_key[240];
    int rounds;
} sc_aes_key;

typedef struct {
    uint32_t rk[32];
} sc_sm4_key;

typedef struct {
    uint8_t key[16];
} sc_gift_key;

typedef struct {
    uint8_t rk[36][8];
} sc_twine_key;

typedef struct {
    uint32_t magic;
    sc_algorithm algorithm;
    sc_backend backend;
    size_t block_size;
    union {
        sc_aes_key aes;
        sc_sm4_key sm4;
        sc_gift_key gift;
        sc_twine_key twine;
    } key;
} sc_internal_ctx;

_Static_assert(sizeof(sc_internal_ctx) <= sizeof(sc_ctx), "sc_ctx is too small");

static inline sc_internal_ctx *sc_mut(sc_ctx *ctx) {
    return (sc_internal_ctx *)(void *)ctx;
}

static inline const sc_internal_ctx *sc_const(const sc_ctx *ctx) {
    return (const sc_internal_ctx *)(const void *)ctx;
}

uint32_t sc_load_be32(const uint8_t p[4]);
void sc_store_be32(uint8_t p[4], uint32_t x);
uint64_t sc_load_be64(const uint8_t p[8]);
void sc_store_be64(uint8_t p[8], uint64_t x);
uint32_t sc_rotl32(uint32_t x, unsigned n);
uint8_t sc_aes_inv_sbox_byte(uint8_t x);
uint8_t sc_sm4_sbox_byte(uint8_t x);

sc_status sc_aes_setkey(sc_aes_key *key, const uint8_t *raw, size_t len);
void sc_aes_encrypt_ref(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]);
void sc_aes_decrypt_ref(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]);
void sc_aes_encrypt_ttable(const sc_aes_key *key, const uint8_t in[16],
                           uint8_t out[16]);
void sc_aes_decrypt_ttable(const sc_aes_key *key, const uint8_t in[16],
                           uint8_t out[16]);

sc_status sc_sm4_setkey(sc_sm4_key *key, const uint8_t raw[16]);
void sc_sm4_encrypt_ref(const sc_sm4_key *key, const uint8_t in[16],
                        uint8_t out[16]);
void sc_sm4_decrypt_ref(const sc_sm4_key *key, const uint8_t in[16],
                        uint8_t out[16]);
void sc_sm4_encrypt_ttable(const sc_sm4_key *key, const uint8_t in[16],
                           uint8_t out[16], sc_backend backend);

void sc_gift_setkey(sc_gift_key *key, const uint8_t raw[16]);
void sc_gift_encrypt(const sc_gift_key *key, const uint8_t in[8],
                     uint8_t out[8]);
void sc_gift_decrypt(const sc_gift_key *key, const uint8_t in[8],
                     uint8_t out[8]);
void sc_gift_encrypt4(const sc_gift_key *key, const uint8_t in[32],
                      uint8_t out[32]);
void sc_gift_decrypt4(const sc_gift_key *key, const uint8_t in[32],
                      uint8_t out[32]);

sc_status sc_twine_setkey(sc_twine_key *key, const uint8_t *raw, size_t len);
void sc_twine_encrypt(const sc_twine_key *key, const uint8_t in[8],
                      uint8_t out[8]);
void sc_twine_decrypt(const sc_twine_key *key, const uint8_t in[8],
                      uint8_t out[8]);

int sc_arm_aes_available(void);
void sc_arm_aes_encrypt(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]);
void sc_arm_aes_decrypt(const sc_aes_key *key, const uint8_t in[16],
                        uint8_t out[16]);
void sc_arm_aes_encrypt4(const sc_aes_key *key, const uint8_t in[64],
                         uint8_t out[64]);
void sc_arm_aes_decrypt4(const sc_aes_key *key, const uint8_t in[64],
                         uint8_t out[64]);
void sc_x86_aes_encrypt8_vaes(const sc_aes_key *key, const uint8_t in[128],
                               uint8_t out[128]);
void sc_x86_aes_decrypt8_vaes(const sc_aes_key *key, const uint8_t in[128],
                               uint8_t out[128]);
void sc_arm_sm4_encrypt_shuffle(const sc_sm4_key *key, const uint8_t in[16],
                                uint8_t out[16]);
void sc_arm_sm4_encrypt4_shuffle(const sc_sm4_key *key, const uint8_t in[64],
                                 uint8_t out[64]);
void sc_arm_twine_encrypt_shuffle(const sc_twine_key *key, const uint8_t in[8],
                                  uint8_t out[8]);
void sc_arm_twine_crypt4_shuffle(const sc_twine_key *key, const uint8_t in[32],
                                 uint8_t out[32], int decrypt);
void sc_x86_sm4_encrypt4_shuffle(const sc_sm4_key *key, const uint8_t in[64],
                                  uint8_t out[64]);
void sc_x86_twine_crypt4_shuffle(const sc_twine_key *key,
                                  const uint8_t in[32], uint8_t out[32],
                                  int decrypt);
uint8_t sc_sm4_gfni_scalar_model(uint8_t x);
uint8_t sc_x86_sm4_gfni_sbox_byte(uint8_t x);
int sc_arm_ghash_mul(uint8_t x[16], const uint8_t h[16]);
int sc_x86_ghash_mul(uint8_t x[16], const uint8_t h[16]);
int sc_x86_ghash_mul_pclmul(uint8_t x[16], const uint8_t h[16]);
int sc_x86_ghash_mul_vpclmul(uint8_t x[16], const uint8_t h[16]);
void sc_x86_sm4_encrypt_gfni(const sc_sm4_key *key, const uint8_t in[16],
                             uint8_t out[16]);
void sc_x86_sm4_encrypt4_gfni(const sc_sm4_key *key, const uint8_t in[64],
                              uint8_t out[64]);
void sc_arm_sm4_setkey_hw(sc_sm4_key *key, const uint8_t raw[16]);
void sc_arm_sm4_encrypt4_hw(const sc_sm4_key *key, const uint8_t in[64],
                            uint8_t out[64]);
void sc_x86_sm4_encrypt8_hw(const sc_sm4_key *key, const uint8_t in[128],
                            uint8_t out[128]);
void sc_sm4_encrypt4_aes_assist(const sc_sm4_key *key, const uint8_t in[64],
                                uint8_t out[64]);

#endif
