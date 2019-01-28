//
// arch/x86_64/rsp/vsubc.h
//
// This file is subject to the terms and conditions defined in
// 'LICENSE', which is part of this source code package.
//

static inline __m128i rsp_vsubc(__m128i vs, __m128i vt,
  __m128i zero, __m128i *eq, __m128i *sn) {
  __m128i equal, sat_udiff, sat_udiff_zero;

  sat_udiff = simde_mm_subs_epu16(vs, vt);
  equal = simde_mm_cmpeq_epi16(vs, vt);
  sat_udiff_zero = simde_mm_cmpeq_epi16(sat_udiff, zero);

  *eq = simde_mm_cmpeq_epi16(equal, zero);
  *sn = simde_mm_andnot_si128(equal, sat_udiff_zero);

  return simde_mm_sub_epi16(vs, vt);
}

