#include "../internal.h"

#if defined(__aarch64__) || defined(__arm64__)
#include <arm_neon.h>

static uint64_t reverse64(uint64_t x) {
    x = ((x & UINT64_C(0x5555555555555555)) << 1) |
        ((x >> 1) & UINT64_C(0x5555555555555555));
    x = ((x & UINT64_C(0x3333333333333333)) << 2) |
        ((x >> 2) & UINT64_C(0x3333333333333333));
    x = ((x & UINT64_C(0x0f0f0f0f0f0f0f0f)) << 4) |
        ((x >> 4) & UINT64_C(0x0f0f0f0f0f0f0f0f));
    x = ((x & UINT64_C(0x00ff00ff00ff00ff)) << 8) |
        ((x >> 8) & UINT64_C(0x00ff00ff00ff00ff));
    x = ((x & UINT64_C(0x0000ffff0000ffff)) << 16) |
        ((x >> 16) & UINT64_C(0x0000ffff0000ffff));
    return (x << 32) | (x >> 32);
}

int sc_arm_ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    if (!sc_detect_cpu_features().arm_pmull) return 0;
    uint64_t al = reverse64(sc_load_be64(x));
    uint64_t ah = reverse64(sc_load_be64(x + 8));
    uint64_t bl = reverse64(sc_load_be64(h));
    uint64_t bh = reverse64(sc_load_be64(h + 8));
    uint64x2_t p0 = vreinterpretq_u64_p128(vmull_p64((poly64_t)al, (poly64_t)bl));
    uint64x2_t p1 = vreinterpretq_u64_p128(vmull_p64((poly64_t)ah, (poly64_t)bh));
    uint64x2_t pc = vreinterpretq_u64_p128(
        vmull_p64((poly64_t)(al ^ ah), (poly64_t)(bl ^ bh)));
    uint64_t cross0 = vgetq_lane_u64(pc, 0) ^
                      vgetq_lane_u64(p0, 0) ^ vgetq_lane_u64(p1, 0);
    uint64_t cross1 = vgetq_lane_u64(pc, 1) ^
                      vgetq_lane_u64(p0, 1) ^ vgetq_lane_u64(p1, 1);
    uint64_t z0 = vgetq_lane_u64(p0, 0);
    uint64_t z1 = vgetq_lane_u64(p0, 1) ^ cross0;
    uint64_t h0 = vgetq_lane_u64(p1, 0) ^ cross1;
    uint64_t h1 = vgetq_lane_u64(p1, 1);
    /*
     * Fold H*x^128 with x^128 = x^7+x^2+x+1.  The first fold can
     * overflow by at most seven bits; q is folded once more.
     */
    uint64_t q = (h1 >> 63) ^ (h1 >> 62) ^ (h1 >> 57);
    z0 ^= h0 ^ (h0 << 1) ^ (h0 << 2) ^ (h0 << 7);
    z1 ^= h1 ^ (h1 << 1) ^ (h1 << 2) ^ (h1 << 7) ^
          (h0 >> 63) ^ (h0 >> 62) ^ (h0 >> 57);
    z0 ^= q ^ (q << 1) ^ (q << 2) ^ (q << 7);
    uint64_t z[2] = {
        z0, z1
    };
    sc_store_be64(x, reverse64(z[0]));
    sc_store_be64(x + 8, reverse64(z[1]));
    return 1;
}

#else
int sc_arm_ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    (void)x;
    (void)h;
    return 0;
}
#endif
