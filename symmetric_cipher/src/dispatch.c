#include "internal.h"

#include <stdatomic.h>
#include <string.h>

#if defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif
#if defined(__linux__) && (defined(__aarch64__) || defined(__arm64__))
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>

static uint64_t sc_xgetbv0(void) {
    uint32_t eax, edx;
    __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
    return ((uint64_t)edx << 32) | eax;
}
#endif

static int valid_ctx(const sc_ctx *ctx) {
    return ctx != NULL && sc_const(ctx)->magic == SC_MAGIC;
}

static sc_sm4_key sm4_reverse_key(const sc_sm4_key *key) {
    sc_sm4_key reversed;
    for (size_t i = 0; i < 32; ++i) reversed.rk[i] = key->rk[31U - i];
    return reversed;
}

static void sm4_hw_encrypt_one(const sc_sm4_key *key, const uint8_t in[16],
                               uint8_t out[16]) {
    uint8_t lanes[128] = {0};
    memcpy(lanes, in, 16);
    if (sc_detect_cpu_features().x86_sm4)
        sc_x86_sm4_encrypt8_hw(key, lanes, lanes);
    else
        sc_arm_sm4_encrypt4_hw(key, lanes, lanes);
    memcpy(out, lanes, 16);
}

const char *sc_algorithm_name(sc_algorithm a) {
    static const char *names[] = {
        "AES-128","AES-192","AES-256","SM4-128",
        "GIFT-64/128","TWINE-80","TWINE-128"
    };
    return (unsigned)a < sizeof(names) / sizeof(names[0]) ? names[a] : "unknown";
}

const char *sc_backend_name(sc_backend b) {
    static const char *names[] = {
        "auto","ref","ttable-4k","ttable-1k","ttable-2k",
        "shuffle","aes-hw","gfni","sm4-hw"
    };
    return (unsigned)b < sizeof(names) / sizeof(names[0]) ? names[b] : "unknown";
}

static sc_cpu_features detect_cpu_features_uncached(void) {
    sc_cpu_features f;
    memset(&f, 0, sizeof(f));
#if defined(__aarch64__) || defined(__arm64__)
# if defined(__APPLE__)
    int value = 0;
    size_t value_len = sizeof(value);
    if (sysctlbyname("hw.optional.arm.FEAT_AES", &value, &value_len, NULL, 0) == 0)
        f.arm_aes = value != 0;
    else
        f.arm_aes = 1; /* Every shipping Apple Silicon CPU has FEAT_AES. */
    value = 0; value_len = sizeof(value);
    if (sysctlbyname("hw.optional.arm.FEAT_PMULL", &value, &value_len, NULL, 0) == 0)
        f.arm_pmull = value != 0;
    else
        f.arm_pmull = 1;
    value = 0; value_len = sizeof(value);
    if (sysctlbyname("hw.optional.arm.FEAT_SM4", &value, &value_len, NULL, 0) == 0)
        f.arm_sm4 = value != 0;
# elif defined(__linux__)
    unsigned long hwcap = getauxval(AT_HWCAP);
#  ifdef HWCAP_AES
    f.arm_aes = (hwcap & HWCAP_AES) != 0;
#  endif
#  ifdef HWCAP_PMULL
    f.arm_pmull = (hwcap & HWCAP_PMULL) != 0;
#  endif
#  ifdef HWCAP_SM4
    f.arm_sm4 = (hwcap & HWCAP_SM4) != 0;
#  endif
# elif defined(__ARM_FEATURE_CRYPTO)
    f.arm_aes = 1;
    f.arm_pmull = 1;
#  if defined(__ARM_FEATURE_SM4)
    f.arm_sm4 = 1;
#  endif
# endif
#elif defined(__x86_64__) || defined(__i386__)
    unsigned eax, ebx, ecx, edx;
    unsigned max_leaf = __get_cpuid_max(0, NULL);
    int avx_state = 0;
    if (max_leaf >= 1) {
        __cpuid_count(1, 0, eax, ebx, ecx, edx);
        f.x86_pclmul = (int)((ecx >> 1) & 1U);
        f.x86_ssse3 = (int)((ecx >> 9) & 1U);
        f.x86_aesni = (int)((ecx >> 25) & 1U);
        if ((ecx & (1U << 27)) && (ecx & (1U << 28)))
            avx_state = (sc_xgetbv0() & 0x6U) == 0x6U;
    }
    if (max_leaf >= 7) {
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        unsigned max_subleaf = eax;
        f.x86_avx2 = avx_state && (int)((ebx >> 5) & 1U);
        f.x86_gfni = avx_state && (int)((ecx >> 8) & 1U);
        f.x86_vaes = avx_state && (int)((ecx >> 9) & 1U);
        f.x86_vpclmul = avx_state && (int)((ecx >> 10) & 1U);
        if (max_subleaf >= 1) {
            __cpuid_count(7, 1, eax, ebx, ecx, edx);
            f.x86_sm4 = avx_state && (int)((eax >> 2) & 1U);
        }
    }
#endif
    return f;
}

sc_cpu_features sc_detect_cpu_features(void) {
    static sc_cpu_features cached;
    static atomic_flag lock = ATOMIC_FLAG_INIT;
    static atomic_int ready;
    if (atomic_load_explicit(&ready, memory_order_acquire)) return cached;
    while (atomic_flag_test_and_set_explicit(&lock, memory_order_acquire)) { }
    if (!atomic_load_explicit(&ready, memory_order_relaxed)) {
        cached = detect_cpu_features_uncached();
        atomic_store_explicit(&ready, 1, memory_order_release);
    }
    atomic_flag_clear_explicit(&lock, memory_order_release);
    return cached;
}

static sc_status choose_backend(sc_algorithm a, sc_backend requested,
                                sc_backend *chosen) {
    sc_cpu_features f = sc_detect_cpu_features();
    if (requested == SC_BACKEND_AUTO) {
        if (a <= SC_AES_256 && (f.arm_aes || f.x86_aesni)) {
            *chosen = SC_BACKEND_AES_HW;
            return SC_OK;
        }
        if (a == SC_SM4_128 && (f.arm_sm4 || f.x86_sm4)) {
            *chosen = SC_BACKEND_SM4_HW;
            return SC_OK;
        }
        if (a == SC_SM4_128 &&
            (f.arm_aes || (f.x86_aesni && f.x86_ssse3))) {
            *chosen = SC_BACKEND_AES_HW;
            return SC_OK;
        }
        *chosen = SC_BACKEND_REF;
        return SC_OK;
    }
    if (requested == SC_BACKEND_TTABLE &&
        (a <= SC_AES_256 || a == SC_SM4_128)) {
        *chosen = requested;
        return SC_OK;
    }
    if ((requested == SC_BACKEND_TTABLE_1K ||
         requested == SC_BACKEND_TTABLE_2K) && a == SC_SM4_128) {
        *chosen = requested;
        return SC_OK;
    }
    if (requested == SC_BACKEND_SHUFFLE &&
        (a == SC_GIFT64_128 ||
         ((a == SC_SM4_128 || a == SC_TWINE_80 || a == SC_TWINE_128) &&
          (f.arm_aes || f.x86_ssse3)))) {
        *chosen = requested;
        return SC_OK;
    }
    if (requested == SC_BACKEND_AES_HW &&
        ((a <= SC_AES_256 && (f.arm_aes || f.x86_aesni)) ||
         (a == SC_SM4_128 &&
          (f.arm_aes || (f.x86_aesni && f.x86_ssse3))))) {
        *chosen = requested;
        return SC_OK;
    }
    if (requested == SC_BACKEND_GFNI && a == SC_SM4_128 && f.x86_gfni) {
        *chosen = requested;
        return SC_OK;
    }
    if (requested == SC_BACKEND_SM4_HW && a == SC_SM4_128 &&
        (f.arm_sm4 || f.x86_sm4)) {
        *chosen = requested;
        return SC_OK;
    }
    if (requested == SC_BACKEND_REF) {
        *chosen = requested;
        return SC_OK;
    }
    return SC_ERR_UNSUPPORTED;
}

sc_status sc_init(sc_ctx *ctx, sc_algorithm algorithm, sc_backend requested,
                  const uint8_t *key, size_t key_len) {
    if (ctx == NULL || key == NULL || (unsigned)algorithm > SC_TWINE_128)
        return SC_ERR_ARGUMENT;
    memset(ctx, 0, sizeof(*ctx));
    sc_internal_ctx *c = sc_mut(ctx);
    sc_status rc = choose_backend(algorithm, requested, &c->backend);
    if (rc != SC_OK) return rc;
    c->algorithm = algorithm;
    switch (algorithm) {
    case SC_AES_128:
        if (key_len != 16) return SC_ERR_KEY_SIZE;
        c->block_size = 16;
        rc = sc_aes_setkey(&c->key.aes, key, key_len);
        break;
    case SC_AES_192:
        if (key_len != 24) return SC_ERR_KEY_SIZE;
        c->block_size = 16;
        rc = sc_aes_setkey(&c->key.aes, key, key_len);
        break;
    case SC_AES_256:
        if (key_len != 32) return SC_ERR_KEY_SIZE;
        c->block_size = 16;
        rc = sc_aes_setkey(&c->key.aes, key, key_len);
        break;
    case SC_SM4_128:
        if (key_len != 16) return SC_ERR_KEY_SIZE;
        c->block_size = 16;
        if (c->backend == SC_BACKEND_SM4_HW &&
            sc_detect_cpu_features().arm_sm4) {
            sc_arm_sm4_setkey_hw(&c->key.sm4, key);
            rc = SC_OK;
        } else {
            rc = sc_sm4_setkey(&c->key.sm4, key);
        }
        break;
    case SC_GIFT64_128:
        if (key_len != 16) return SC_ERR_KEY_SIZE;
        c->block_size = 8;
        sc_gift_setkey(&c->key.gift, key);
        rc = SC_OK;
        break;
    case SC_TWINE_80:
        c->block_size = 8;
        rc = sc_twine_setkey(&c->key.twine, key, key_len);
        break;
    case SC_TWINE_128:
        c->block_size = 8;
        rc = sc_twine_setkey(&c->key.twine, key, key_len);
        break;
    }
    if (rc == SC_OK) c->magic = SC_MAGIC;
    return rc;
}

sc_status sc_encrypt_block(const sc_ctx *ctx, const uint8_t *in, uint8_t *out) {
    if (!valid_ctx(ctx) || in == NULL || out == NULL) return SC_ERR_ARGUMENT;
    const sc_internal_ctx *c = sc_const(ctx);
    uint8_t tmp[SC_MAX_BLOCK];
    const uint8_t *src = in;
    if (in == out) {
        memcpy(tmp, in, c->block_size);
        src = tmp;
    }
    if (c->algorithm <= SC_AES_256) {
        if (c->backend == SC_BACKEND_TTABLE)
            sc_aes_encrypt_ttable(&c->key.aes, src, out);
        else if (c->backend == SC_BACKEND_AES_HW)
            sc_arm_aes_encrypt(&c->key.aes, src, out);
        else
            sc_aes_encrypt_ref(&c->key.aes, src, out);
    } else if (c->algorithm == SC_SM4_128) {
        if (c->backend == SC_BACKEND_TTABLE ||
            c->backend == SC_BACKEND_TTABLE_1K ||
            c->backend == SC_BACKEND_TTABLE_2K)
            sc_sm4_encrypt_ttable(&c->key.sm4, src, out, c->backend);
        else if (c->backend == SC_BACKEND_SHUFFLE)
            sc_arm_sm4_encrypt_shuffle(&c->key.sm4, src, out);
        else if (c->backend == SC_BACKEND_GFNI)
            sc_x86_sm4_encrypt_gfni(&c->key.sm4, src, out);
        else if (c->backend == SC_BACKEND_AES_HW) {
            uint8_t lanes[64] = {0};
            memcpy(lanes, src, 16);
            sc_sm4_encrypt4_aes_assist(&c->key.sm4, lanes, lanes);
            memcpy(out, lanes, 16);
        }
        else if (c->backend == SC_BACKEND_SM4_HW)
            sm4_hw_encrypt_one(&c->key.sm4, src, out);
        else
            sc_sm4_encrypt_ref(&c->key.sm4, src, out);
    } else if (c->algorithm == SC_GIFT64_128) {
        sc_gift_encrypt(&c->key.gift, src, out);
    } else if (c->backend == SC_BACKEND_SHUFFLE) {
        sc_arm_twine_encrypt_shuffle(&c->key.twine, src, out);
    } else {
        sc_twine_encrypt(&c->key.twine, src, out);
    }
    return SC_OK;
}

sc_status sc_decrypt_block(const sc_ctx *ctx, const uint8_t *in, uint8_t *out) {
    if (!valid_ctx(ctx) || in == NULL || out == NULL) return SC_ERR_ARGUMENT;
    const sc_internal_ctx *c = sc_const(ctx);
    uint8_t tmp[SC_MAX_BLOCK];
    const uint8_t *src = in;
    if (in == out) {
        memcpy(tmp, in, c->block_size);
        src = tmp;
    }
    if (c->algorithm <= SC_AES_256) {
        if (c->backend == SC_BACKEND_AES_HW)
            sc_arm_aes_decrypt(&c->key.aes, src, out);
        else if (c->backend == SC_BACKEND_TTABLE)
            sc_aes_decrypt_ttable(&c->key.aes, src, out);
        else
            sc_aes_decrypt_ref(&c->key.aes, src, out);
    } else if (c->algorithm == SC_SM4_128) {
        if (c->backend == SC_BACKEND_TTABLE ||
            c->backend == SC_BACKEND_TTABLE_1K ||
            c->backend == SC_BACKEND_TTABLE_2K) {
            sc_sm4_key reversed = sm4_reverse_key(&c->key.sm4);
            sc_sm4_encrypt_ttable(&reversed, src, out, c->backend);
        } else if (c->backend == SC_BACKEND_SHUFFLE) {
            sc_sm4_key reversed = sm4_reverse_key(&c->key.sm4);
            sc_arm_sm4_encrypt_shuffle(&reversed, src, out);
        } else if (c->backend == SC_BACKEND_GFNI) {
            sc_sm4_key reversed = sm4_reverse_key(&c->key.sm4);
            sc_x86_sm4_encrypt_gfni(&reversed, src, out);
        } else if (c->backend == SC_BACKEND_AES_HW) {
            sc_sm4_key reversed = sm4_reverse_key(&c->key.sm4);
            uint8_t lanes[64] = {0};
            memcpy(lanes, src, 16);
            sc_sm4_encrypt4_aes_assist(&reversed, lanes, lanes);
            memcpy(out, lanes, 16);
        } else if (c->backend == SC_BACKEND_SM4_HW) {
            sc_sm4_key reversed = sm4_reverse_key(&c->key.sm4);
            sm4_hw_encrypt_one(&reversed, src, out);
        } else {
            sc_sm4_decrypt_ref(&c->key.sm4, src, out);
        }
    }
    else if (c->algorithm == SC_GIFT64_128)
        sc_gift_decrypt(&c->key.gift, src, out);
    else
        sc_twine_decrypt(&c->key.twine, src, out);
    return SC_OK;
}

sc_status sc_encrypt_blocks(const sc_ctx *ctx, const uint8_t *in, uint8_t *out,
                            size_t blocks) {
    if (!valid_ctx(ctx) || (blocks && (in == NULL || out == NULL)))
        return SC_ERR_ARGUMENT;
    const sc_internal_ctx *c = sc_const(ctx);
    size_t bs = c->block_size;
    size_t i = 0;
    if (c->algorithm <= SC_AES_256 && c->backend == SC_BACKEND_AES_HW) {
        if (sc_detect_cpu_features().x86_vaes)
            for (; blocks - i >= 8; i += 8)
                sc_x86_aes_encrypt8_vaes(&c->key.aes, in + i * 16,
                                          out + i * 16);
        for (; blocks - i >= 4; i += 4)
            sc_arm_aes_encrypt4(&c->key.aes, in + i * 16, out + i * 16);
    } else if (c->algorithm == SC_GIFT64_128 &&
               c->backend == SC_BACKEND_SHUFFLE) {
        for (; blocks - i >= 4; i += 4)
            sc_gift_encrypt4(&c->key.gift, in + i * 8, out + i * 8);
    } else if (c->algorithm == SC_SM4_128 &&
               c->backend == SC_BACKEND_SHUFFLE) {
        for (; blocks - i >= 4; i += 4)
            if (sc_detect_cpu_features().x86_ssse3)
                sc_x86_sm4_encrypt4_shuffle(&c->key.sm4, in + i * 16,
                                             out + i * 16);
            else
                sc_arm_sm4_encrypt4_shuffle(&c->key.sm4, in + i * 16,
                                             out + i * 16);
    } else if (c->algorithm == SC_SM4_128 &&
               c->backend == SC_BACKEND_AES_HW) {
        for (; blocks - i >= 4; i += 4)
            sc_sm4_encrypt4_aes_assist(&c->key.sm4, in + i * 16,
                                       out + i * 16);
    } else if (c->algorithm == SC_SM4_128 &&
               c->backend == SC_BACKEND_GFNI) {
        for (; blocks - i >= 4; i += 4)
            sc_x86_sm4_encrypt4_gfni(&c->key.sm4, in + i * 16,
                                     out + i * 16);
    } else if (c->algorithm == SC_SM4_128 &&
               c->backend == SC_BACKEND_SM4_HW) {
        if (sc_detect_cpu_features().x86_sm4)
            for (; blocks - i >= 8; i += 8)
                sc_x86_sm4_encrypt8_hw(&c->key.sm4, in + i * 16,
                                       out + i * 16);
        for (; blocks - i >= 4; i += 4)
            sc_arm_sm4_encrypt4_hw(&c->key.sm4, in + i * 16, out + i * 16);
    } else if ((c->algorithm == SC_TWINE_80 ||
                c->algorithm == SC_TWINE_128) &&
               c->backend == SC_BACKEND_SHUFFLE) {
        for (; blocks - i >= 4; i += 4)
            if (sc_detect_cpu_features().x86_ssse3)
                sc_x86_twine_crypt4_shuffle(&c->key.twine, in + i * 8,
                                             out + i * 8, 0);
            else
                sc_arm_twine_crypt4_shuffle(&c->key.twine, in + i * 8,
                                            out + i * 8, 0);
    }
    for (; i < blocks; ++i) {
        sc_status rc = sc_encrypt_block(ctx, in + i * bs, out + i * bs);
        if (rc != SC_OK) return rc;
    }
    return SC_OK;
}

sc_status sc_decrypt_blocks(const sc_ctx *ctx, const uint8_t *in, uint8_t *out,
                            size_t blocks) {
    if (!valid_ctx(ctx) || (blocks && (in == NULL || out == NULL)))
        return SC_ERR_ARGUMENT;
    const sc_internal_ctx *c = sc_const(ctx);
    size_t bs = c->block_size;
    size_t i = 0;
    if (c->algorithm <= SC_AES_256 && c->backend == SC_BACKEND_AES_HW) {
        if (sc_detect_cpu_features().x86_vaes)
            for (; blocks - i >= 8; i += 8)
                sc_x86_aes_decrypt8_vaes(&c->key.aes, in + i * 16,
                                          out + i * 16);
        for (; blocks - i >= 4; i += 4)
            sc_arm_aes_decrypt4(&c->key.aes, in + i * 16, out + i * 16);
    } else if (c->algorithm == SC_GIFT64_128 &&
               c->backend == SC_BACKEND_SHUFFLE) {
        for (; blocks - i >= 4; i += 4)
            sc_gift_decrypt4(&c->key.gift, in + i * 8, out + i * 8);
    } else if (c->algorithm == SC_SM4_128 &&
               c->backend == SC_BACKEND_SHUFFLE) {
        sc_sm4_key reversed = sm4_reverse_key(&c->key.sm4);
        for (; blocks - i >= 4; i += 4)
            if (sc_detect_cpu_features().x86_ssse3)
                sc_x86_sm4_encrypt4_shuffle(&reversed, in + i * 16,
                                             out + i * 16);
            else
                sc_arm_sm4_encrypt4_shuffle(&reversed, in + i * 16,
                                             out + i * 16);
    } else if (c->algorithm == SC_SM4_128 &&
               c->backend == SC_BACKEND_AES_HW) {
        sc_sm4_key reversed = sm4_reverse_key(&c->key.sm4);
        for (; blocks - i >= 4; i += 4)
            sc_sm4_encrypt4_aes_assist(&reversed, in + i * 16,
                                       out + i * 16);
    } else if (c->algorithm == SC_SM4_128 &&
               c->backend == SC_BACKEND_GFNI) {
        sc_sm4_key reversed = sm4_reverse_key(&c->key.sm4);
        for (; blocks - i >= 4; i += 4)
            sc_x86_sm4_encrypt4_gfni(&reversed, in + i * 16,
                                     out + i * 16);
    } else if (c->algorithm == SC_SM4_128 &&
               c->backend == SC_BACKEND_SM4_HW) {
        sc_sm4_key reversed = sm4_reverse_key(&c->key.sm4);
        if (sc_detect_cpu_features().x86_sm4)
            for (; blocks - i >= 8; i += 8)
                sc_x86_sm4_encrypt8_hw(&reversed, in + i * 16,
                                       out + i * 16);
        for (; blocks - i >= 4; i += 4)
            sc_arm_sm4_encrypt4_hw(&reversed, in + i * 16, out + i * 16);
    } else if ((c->algorithm == SC_TWINE_80 ||
                c->algorithm == SC_TWINE_128) &&
               c->backend == SC_BACKEND_SHUFFLE) {
        for (; blocks - i >= 4; i += 4)
            if (sc_detect_cpu_features().x86_ssse3)
                sc_x86_twine_crypt4_shuffle(&c->key.twine, in + i * 8,
                                             out + i * 8, 1);
            else
                sc_arm_twine_crypt4_shuffle(&c->key.twine, in + i * 8,
                                            out + i * 8, 1);
    }
    for (; i < blocks; ++i) {
        sc_status rc = sc_decrypt_block(ctx, in + i * bs, out + i * bs);
        if (rc != SC_OK) return rc;
    }
    return SC_OK;
}

size_t sc_block_size(const sc_ctx *ctx) {
    return valid_ctx(ctx) ? sc_const(ctx)->block_size : 0;
}

sc_algorithm sc_algorithm_id(const sc_ctx *ctx) {
    return valid_ctx(ctx) ? sc_const(ctx)->algorithm : SC_AES_128;
}

sc_backend sc_backend_id(const sc_ctx *ctx) {
    return valid_ctx(ctx) ? sc_const(ctx)->backend : SC_BACKEND_REF;
}
