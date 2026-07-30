#include "symcrypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t unhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = strlen(s);
    if ((n & 1U) || n / 2 > cap) return 0;
    for (size_t i = 0; i < n / 2; ++i) {
        unsigned x;
        if (sscanf(s + 2 * i, "%2x", &x) != 1) return 0;
        out[i] = (uint8_t)x;
    }
    return n / 2;
}

static int parse_algorithm(const char *s, sc_algorithm *a) {
    static const struct { const char *name; sc_algorithm value; } values[] = {
        {"aes128",SC_AES_128},{"aes192",SC_AES_192},{"aes256",SC_AES_256},
        {"sm4",SC_SM4_128},{"gift64",SC_GIFT64_128},
        {"twine80",SC_TWINE_80},{"twine128",SC_TWINE_128}
    };
    for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); ++i)
        if (strcmp(s, values[i].name) == 0) { *a = values[i].value; return 1; }
    return 0;
}

static int parse_backend(const char *s, sc_backend *b) {
    static const struct { const char *name; sc_backend value; } values[] = {
        {"auto",SC_BACKEND_AUTO},{"ref",SC_BACKEND_REF},
        {"ttable-4k",SC_BACKEND_TTABLE},{"ttable-1k",SC_BACKEND_TTABLE_1K},
        {"ttable-2k",SC_BACKEND_TTABLE_2K},{"shuffle",SC_BACKEND_SHUFFLE},
        {"aes-hw",SC_BACKEND_AES_HW},{"gfni",SC_BACKEND_GFNI},
        {"sm4-hw",SC_BACKEND_SM4_HW}
    };
    for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); ++i)
        if (strcmp(s, values[i].name) == 0) { *b = values[i].value; return 1; }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s ALG BACKEND KEY_HEX BLOCK_HEX\n", argv[0]);
        return 2;
    }
    sc_algorithm algorithm;
    sc_backend backend;
    uint8_t key[32], input[16], output[16];
    if (!parse_algorithm(argv[1], &algorithm) ||
        !parse_backend(argv[2], &backend)) return 2;
    size_t key_len = unhex(argv[3], key, sizeof(key));
    size_t block_len = unhex(argv[4], input, sizeof(input));
    sc_ctx ctx;
    sc_status status = sc_init(&ctx, algorithm, backend, key, key_len);
    if (status != SC_OK) {
        fprintf(stderr, "init failed: %d (unsupported ISA paths are not emulated)\n", status);
        return 1;
    }
    if (block_len != sc_block_size(&ctx) ||
        sc_encrypt_block(&ctx, input, output) != SC_OK) return 2;
    printf("%s/%s: ", sc_algorithm_name(algorithm),
           sc_backend_name(sc_backend_id(&ctx)));
    for (size_t i = 0; i < block_len; ++i) printf("%02x", output[i]);
    putchar('\n');
    return 0;
}
