//
// arch/x86_64/rsp/vxor.h
//
// This file is subject to the terms and conditions defined in
// 'LICENSE', which is part of this source code package.
//

static inline __m128i rsp_vxor(__m128i vs, __m128i vt) {
  return simde_mm_xor_si128(vs, vt);
}

static inline __m128i rsp_vnxor(__m128i vs, __m128i vt) {
  __m128i vd = simde_mm_xor_si128(vs, vt);
  return simde_mm_xor_si128(vd, simde_mm_set1_epi32(0xffffffffu));
}

