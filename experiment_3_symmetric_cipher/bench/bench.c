#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "symcrypto.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/utsname.h>
#endif
#include <time.h>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#include <immintrin.h>
#endif

enum operation {
    OP_BLOCK, OP_BLOCK_DEC, OP_CTR, OP_GCM, OP_GCM_DEC, OP_XTS, OP_XTS_DEC
};

typedef struct {
    sc_algorithm algorithm;
    sc_backend backend;
    enum operation operation;
    const char *label;
} bench_case;

static const bench_case cases[] = {
    {SC_AES_128,SC_BACKEND_REF,OP_BLOCK,"block"},
    {SC_AES_128,SC_BACKEND_TTABLE,OP_BLOCK,"block"},
    {SC_AES_128,SC_BACKEND_AUTO,OP_BLOCK,"block"},
    {SC_AES_128,SC_BACKEND_AUTO,OP_BLOCK_DEC,"block-dec"},
    {SC_SM4_128,SC_BACKEND_REF,OP_BLOCK,"block"},
    {SC_SM4_128,SC_BACKEND_TTABLE,OP_BLOCK,"block"},
    {SC_SM4_128,SC_BACKEND_TTABLE_1K,OP_BLOCK,"block"},
    {SC_SM4_128,SC_BACKEND_TTABLE_2K,OP_BLOCK,"block"},
    {SC_SM4_128,SC_BACKEND_SHUFFLE,OP_BLOCK,"block"},
    {SC_SM4_128,SC_BACKEND_AES_HW,OP_BLOCK,"block"},
    {SC_SM4_128,SC_BACKEND_GFNI,OP_BLOCK,"block"},
    {SC_SM4_128,SC_BACKEND_SM4_HW,OP_BLOCK,"block"},
    {SC_SM4_128,SC_BACKEND_TTABLE_2K,OP_BLOCK_DEC,"block-dec"},
    {SC_SM4_128,SC_BACKEND_GFNI,OP_BLOCK_DEC,"block-dec"},
    {SC_GIFT64_128,SC_BACKEND_REF,OP_BLOCK,"block"},
    {SC_GIFT64_128,SC_BACKEND_SHUFFLE,OP_BLOCK,"block"},
    {SC_TWINE_80,SC_BACKEND_REF,OP_BLOCK,"block"},
    {SC_TWINE_80,SC_BACKEND_SHUFFLE,OP_BLOCK,"block"},
    {SC_TWINE_128,SC_BACKEND_REF,OP_BLOCK,"block"},
    {SC_AES_128,SC_BACKEND_AUTO,OP_CTR,"ctr"},
    {SC_SM4_128,SC_BACKEND_TTABLE_2K,OP_CTR,"ctr"},
    {SC_SM4_128,SC_BACKEND_AUTO,OP_CTR,"ctr"},
    {SC_GIFT64_128,SC_BACKEND_REF,OP_CTR,"ctr"},
    {SC_GIFT64_128,SC_BACKEND_SHUFFLE,OP_CTR,"ctr"},
    {SC_TWINE_80,SC_BACKEND_SHUFFLE,OP_CTR,"ctr"},
    {SC_AES_128,SC_BACKEND_AUTO,OP_GCM,"gcm"},
    {SC_AES_128,SC_BACKEND_AUTO,OP_GCM_DEC,"gcm-dec"},
    {SC_SM4_128,SC_BACKEND_REF,OP_GCM,"gcm"},
    {SC_SM4_128,SC_BACKEND_AUTO,OP_GCM,"gcm"},
    {SC_SM4_128,SC_BACKEND_AUTO,OP_GCM_DEC,"gcm-dec"},
    {SC_AES_128,SC_BACKEND_AUTO,OP_XTS,"xts"},
    {SC_AES_128,SC_BACKEND_AUTO,OP_XTS_DEC,"xts-dec"},
    {SC_SM4_128,SC_BACKEND_REF,OP_XTS,"xts-ieee"},
    {SC_SM4_128,SC_BACKEND_REF,OP_XTS,"xts-gb"},
    {SC_SM4_128,SC_BACKEND_REF,OP_XTS_DEC,"xts-gb-dec"},
    {SC_SM4_128,SC_BACKEND_AUTO,OP_XTS,"xts-gb"},
    {SC_SM4_128,SC_BACKEND_AUTO,OP_XTS_DEC,"xts-gb-dec"}
};

static const size_t sizes[] = {64,512,4096,8192,65536,1048576};
static volatile uint8_t sink;

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) abort();
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static int tsc_available(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned max_extended = __get_cpuid_max(0x80000000U, NULL);
    unsigned eax, ebx, ecx, edx;
    if (max_extended < 0x80000001U) return 0;
    __cpuid_count(0x80000001U, 0, eax, ebx, ecx, edx);
    return (int)((edx >> 27) & 1U);
#else
    return 0;
#endif
}

static uint64_t read_tsc(unsigned *aux) {
#if defined(__x86_64__) || defined(__i386__)
    _mm_lfence();
    unsigned low, high, aux_value;
    __asm__ volatile("rdtscp" : "=a"(low), "=d"(high), "=c"(aux_value));
    *aux = aux_value;
    uint64_t value = ((uint64_t)high << 32) | low;
    _mm_lfence();
    return value;
#else
    *aux = 0;
    return 0;
#endif
}

static size_t key_length(sc_algorithm a) {
    if (a == SC_TWINE_80) return 10;
    if (a == SC_AES_192) return 24;
    if (a == SC_AES_256) return 32;
    return 16;
}

static const char *actual_backend_name(sc_algorithm a, sc_backend requested,
                                       const uint8_t key[32]) {
    static sc_ctx tmp;
    if (sc_init(&tmp, a, requested, key, key_length(a)) != SC_OK)
        return "unsupported";
    return sc_backend_name(sc_backend_id(&tmp));
}

static sc_status run_once(const bench_case *bc, const sc_ctx *ctx,
                          const sc_ctx *tweak_ctx, const uint8_t *in,
                          uint8_t *out, size_t n, unsigned nonce,
                          const uint8_t prepared_tag[16]) {
    uint8_t counter[16] = {0}, iv[12] = {0}, tag[16], tweak[16] = {0};
    counter[0] = (uint8_t)(nonce >> 8);
    counter[1] = (uint8_t)nonce;
    iv[10] = (uint8_t)(nonce >> 8);
    iv[11] = (uint8_t)nonce;
    if (bc->operation != OP_XTS_DEC) tweak[0] = (uint8_t)nonce;
    if (bc->operation == OP_BLOCK)
        return sc_encrypt_blocks(ctx, in, out, n / sc_block_size(ctx));
    if (bc->operation == OP_BLOCK_DEC)
        return sc_decrypt_blocks(ctx, in, out, n / sc_block_size(ctx));
    if (bc->operation == OP_CTR)
        return sc_ctr_xor(ctx, counter, in, out, n);
    if (bc->operation == OP_GCM)
        return sc_gcm_encrypt(ctx, iv, sizeof(iv), in, n > 31 ? 31 : n,
                              in, out, n, tag, sizeof(tag));
    if (bc->operation == OP_GCM_DEC) {
        memset(iv, 0, sizeof(iv));
        return sc_gcm_decrypt(ctx, iv, sizeof(iv), NULL, 0,
                              in, out, n, prepared_tag, 16);
    }
    sc_xts_convention convention =
        strstr(bc->label, "gb") != NULL ? SC_XTS_GBT_BE : SC_XTS_IEEE_LE;
    if (bc->operation == OP_XTS_DEC)
        return sc_xts_decrypt(ctx, tweak_ctx, tweak, in, out, n, convention);
    return sc_xts_encrypt(ctx, tweak_ctx, tweak, in, out, n,
                          convention);
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static const char *compiler_name(void) {
#if defined(__clang__)
    return "clang-" __clang_version__;
#elif defined(__GNUC__)
    return "gcc-" __VERSION__;
#else
    return "unknown";
#endif
}

static void cpu_name(char *out, size_t cap) {
#if defined(__APPLE__)
    size_t n = cap;
    if (sysctlbyname("machdep.cpu.brand_string", out, &n, NULL, 0) == 0 &&
        n > 1) return;
    n = cap;
    if (sysctlbyname("hw.model", out, &n, NULL, 0) == 0 && n > 1) return;
#endif
#if defined(__x86_64__) || defined(__i386__)
    unsigned max_extended = __get_cpuid_max(0x80000000U, NULL);
    if (max_extended >= 0x80000004U) {
        unsigned words[12];
        for (unsigned leaf = 0; leaf < 3; ++leaf)
            __cpuid_count(0x80000002U + leaf, 0, words[4 * leaf],
                          words[4 * leaf + 1], words[4 * leaf + 2],
                          words[4 * leaf + 3]);
        char brand[49];
        memcpy(brand, words, 48);
        brand[48] = '\0';
        const char *first = brand;
        while (*first == ' ') ++first;
        snprintf(out, cap, "%s", first);
        return;
    }
#endif
    snprintf(out, cap, "unknown");
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s raw.csv summary.json\n", argv[0]);
        return 2;
    }
    FILE *raw = fopen(argv[1], "w");
    FILE *summary = fopen(argv[2], "w");
    if (!raw || !summary) {
        fprintf(stderr, "open output: %s\n", strerror(errno));
        return 2;
    }
    char system_name[64], machine[64];
#if defined(_WIN32)
    snprintf(system_name, sizeof(system_name), "Windows");
# if defined(__x86_64__)
    snprintf(machine, sizeof(machine), "x86_64");
# else
    snprintf(machine, sizeof(machine), "x86");
# endif
#else
    struct utsname un;
    if (uname(&un) != 0) memset(&un, 0, sizeof(un));
    snprintf(system_name, sizeof(system_name), "%s", un.sysname);
    snprintf(machine, sizeof(machine), "%s", un.machine);
#endif
    char cpu[128];
    cpu_name(cpu, sizeof(cpu));
    sc_cpu_features features = sc_detect_cpu_features();
    int have_tsc = tsc_available();
    fprintf(raw, "platform,cpu,compiler,algorithm,backend,operation,size_bytes,"
                 "sample,elapsed_ns,bytes_processed,ns_per_byte,gbps,cycles_per_byte,status\n");
    fprintf(summary,
            "{\n  \"schema\": 2,\n  \"platform\": \"%s %s\",\n"
            "  \"architecture\": \"%s\",\n"
            "  \"cpu\": \"%s\",\n  \"compiler\": \"%s\",\n"
            "  \"warmups\": 3,\n  \"samples\": 15,\n"
            "  \"steady_state_key_expansion_excluded\": true,\n"
            "  \"cycle_counter\": \"%s\",\n"
            "  \"features\": {\"aesni\":%d,\"ssse3\":%d,\"avx2\":%d,"
            "\"vaes\":%d,\"pclmul\":%d,\"vpclmul\":%d,\"gfni\":%d,"
            "\"vsm4\":%d},\n"
            "  \"results\": [\n",
            system_name, machine, machine, cpu, compiler_name(),
            have_tsc ? "rdtscp_tsc_ticks" : "unavailable",
            features.x86_aesni, features.x86_ssse3, features.x86_avx2,
            features.x86_vaes, features.x86_pclmul, features.x86_vpclmul,
            features.x86_gfni, features.x86_sm4);
    uint8_t *in = malloc(sizes[sizeof(sizes)/sizeof(sizes[0]) - 1]);
    uint8_t *out = malloc(sizes[sizeof(sizes)/sizeof(sizes[0]) - 1]);
    uint8_t *prepared = malloc(sizes[sizeof(sizes)/sizeof(sizes[0]) - 1]);
    if (!in || !out || !prepared) return 2;
    for (size_t i = 0; i < sizes[sizeof(sizes)/sizeof(sizes[0]) - 1]; ++i)
        in[i] = (uint8_t)(i * 131U + 17U);
    int first_json = 1;
    uint8_t key[32], tweak_key[32];
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (uint8_t)(i * 13U + 1U);
        tweak_key[i] = (uint8_t)(i * 7U + 0x80U);
    }
    for (size_t ci = 0; ci < sizeof(cases)/sizeof(cases[0]); ++ci) {
        const bench_case *bc = &cases[ci];
        sc_ctx ctx, tweak_ctx;
        sc_status init = sc_init(&ctx, bc->algorithm, bc->backend, key,
                                 key_length(bc->algorithm));
        sc_status tweak_init = SC_OK;
        if (bc->operation == OP_XTS || bc->operation == OP_XTS_DEC)
            tweak_init = sc_init(&tweak_ctx, bc->algorithm, bc->backend,
                                 tweak_key, key_length(bc->algorithm));
        if (init != SC_OK || tweak_init != SC_OK) continue;
        const char *backend = actual_backend_name(bc->algorithm, bc->backend, key);
        for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); ++si) {
            size_t n = sizes[si];
            const uint8_t *bench_in = in;
            uint8_t prepared_tag[16] = {0};
            uint8_t zero_iv[12] = {0}, zero_tweak[16] = {0};
            if (bc->operation == OP_BLOCK_DEC) {
                if (sc_encrypt_blocks(&ctx, in, prepared,
                                      n / sc_block_size(&ctx)) != SC_OK) return 3;
                bench_in = prepared;
            } else if (bc->operation == OP_GCM_DEC) {
                if (sc_gcm_encrypt(&ctx, zero_iv, sizeof(zero_iv), NULL,
                                   0, in, prepared, n,
                                   prepared_tag, 16) != SC_OK) return 3;
                bench_in = prepared;
            } else if (bc->operation == OP_XTS_DEC) {
                sc_xts_convention convention =
                    strstr(bc->label, "gb") != NULL ?
                    SC_XTS_GBT_BE : SC_XTS_IEEE_LE;
                if (sc_xts_encrypt(&ctx, &tweak_ctx, zero_tweak, in,
                                   prepared, n, convention) != SC_OK) return 3;
                bench_in = prepared;
            }
            size_t repetitions = (UINT32_C(262144) + n - 1) / n;
            for (unsigned w = 0; w < 3; ++w)
                for (size_t r = 0; r < repetitions; ++r)
                    if (run_once(bc, &ctx, &tweak_ctx, bench_in, out, n,
                                 w * 101U + (unsigned)r,
                                 prepared_tag) != SC_OK) return 3;
            double samples_ns_per_byte[15];
            double samples_tsc_per_byte[15];
            for (unsigned sample = 0; sample < 15; ++sample) {
                unsigned aux_start = 0, aux_end = 0;
                uint64_t cycle_start = have_tsc ? read_tsc(&aux_start) : 0;
                uint64_t start = now_ns();
                sc_status status = SC_OK;
                for (size_t r = 0; r < repetitions; ++r) {
                    status = run_once(bc, &ctx, &tweak_ctx, bench_in, out, n,
                                      sample * 1009U + (unsigned)r,
                                      prepared_tag);
                    if (status != SC_OK) break;
                }
                uint64_t elapsed = now_ns() - start;
                uint64_t cycle_end = have_tsc ? read_tsc(&aux_end) : 0;
                size_t bytes = n * repetitions;
                double ns_per_byte = (double)elapsed / (double)bytes;
                double gbps = 1.0 / ns_per_byte;
                double tsc_per_byte = have_tsc ?
                    (double)(cycle_end - cycle_start) / (double)bytes : 0.0;
                samples_ns_per_byte[sample] = ns_per_byte;
                samples_tsc_per_byte[sample] = tsc_per_byte;
                sink ^= out[(sample * 17U) % n];
                fprintf(raw, "%s-%s,%s,%s,%s,%s,%s,%zu,%u,%llu,%zu,"
                             "%.9f,%.9f,",
                        system_name, machine, cpu, compiler_name(),
                        sc_algorithm_name(bc->algorithm), backend, bc->label,
                        n, sample + 1, (unsigned long long)elapsed, bytes,
                        ns_per_byte, gbps);
                if (have_tsc) fprintf(raw, "%.9f", tsc_per_byte);
                fprintf(raw, ",%s\n", status == SC_OK ? "ok" : "error");
            }
            qsort(samples_ns_per_byte, 15, sizeof(double), cmp_double);
            qsort(samples_tsc_per_byte, 15, sizeof(double), cmp_double);
            double q1 = samples_ns_per_byte[3];
            double median = samples_ns_per_byte[7];
            double q3 = samples_ns_per_byte[11];
            fprintf(summary,
                    "%s    {\"algorithm\":\"%s\",\"backend\":\"%s\","
                    "\"operation\":\"%s\",\"size_bytes\":%zu,"
                    "\"median_ns_per_byte\":%.9f,\"iqr_ns_per_byte\":%.9f,"
                    "\"median_gbps\":%.9f,\"q1_ns_per_byte\":%.9f,"
                    "\"q3_ns_per_byte\":%.9f",
                    first_json ? "" : ",\n", sc_algorithm_name(bc->algorithm),
                    backend, bc->label, n, median, q3 - q1, 1.0 / median, q1, q3);
            if (have_tsc)
                fprintf(summary,
                        ",\"median_tsc_ticks_per_byte\":%.9f,"
                        "\"iqr_tsc_ticks_per_byte\":%.9f,"
                        "\"q1_tsc_ticks_per_byte\":%.9f,"
                        "\"q3_tsc_ticks_per_byte\":%.9f",
                        samples_tsc_per_byte[7],
                        samples_tsc_per_byte[11] - samples_tsc_per_byte[3],
                        samples_tsc_per_byte[3], samples_tsc_per_byte[11]);
            else
                fprintf(summary,
                        ",\"median_tsc_ticks_per_byte\":null,"
                        "\"iqr_tsc_ticks_per_byte\":null,"
                        "\"q1_tsc_ticks_per_byte\":null,"
                        "\"q3_tsc_ticks_per_byte\":null");
            fputc('}', summary);
            first_json = 0;
        }
    }
    fprintf(summary, "\n  ],\n  \"checksum\": %u\n}\n", (unsigned)sink);
    fclose(raw);
    fclose(summary);
    free(in);
    free(out);
    free(prepared);
    printf("wrote %s and %s\n", argv[1], argv[2]);
    return 0;
}
