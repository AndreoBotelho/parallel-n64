//
// arch/x86_64/rsp/vadd.h
//
// This file is subject to the terms and conditions defined in
// 'LICENSE', which is part of this source code package.
//

static inline __m128i rsp_vadd(__m128i vs, __m128i vt,
  __m128i carry, __m128i *acc_lo) {
  __m128i vd, minimum, maximum;

  // VCC uses unsaturated arithmetic.
  vd = simde_mm_add_epi16(vs, vt);
  *acc_lo = simde_mm_sub_epi16(vd, carry);

  // VD is the signed sum of the two sources and the carry. Since we
  // have to saturate the sum of all three, we have to be clever.
  minimum = simde_mm_min_epi16(vs, vt);
  maximum = simde_mm_max_epi16(vs, vt);
  minimum = simde_mm_subs_epi16(minimum, carry);
  return simde_mm_adds_epi16(minimum, maximum);
}

