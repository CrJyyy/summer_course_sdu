#include <arm_neon.h>

__attribute__((noinline))
poly128_t sc_arm_probe_pmull(poly64_t a, poly64_t b) {
    return vmull_p64(a, b);
}

__attribute__((noinline))
uint32x4_t sc_arm_probe_sm4(uint32x4_t state, uint32x4_t round_key) {
    return vsm4eq_u32(state, round_key);
}
