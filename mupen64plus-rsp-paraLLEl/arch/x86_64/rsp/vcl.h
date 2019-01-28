//
// arch/x86_64/rsp/vcl.h
//
// This file is subject to the terms and conditions defined in
// 'LICENSE', which is part of this source code package.
//

static inline __m128i rsp_vcl(__m128i vs, __m128i vt, __m128i zero,
  __m128i *ge, __m128i *le, __m128i eq, __m128i sign, __m128i vce) {

  __m128i sign_negvt, diff, ncarry, nvce, diff_zero;
  __m128i le_case1, le_case2, le_eq, do_le;
  __m128i ge_eq, do_ge, mux_mask;

  // sign_negvt = sign ? -vt : vt
  sign_negvt = simde_mm_xor_si128(vt, sign);
  sign_negvt = simde_mm_sub_epi16(sign_negvt, sign);

  // Compute diff, diff_zero, ncarry, and nvce:
  // Note: diff = sign ? (vs + vt) : (vs - vt).
  diff = simde_mm_sub_epi16(vs, sign_negvt);
  ncarry = simde_mm_adds_epu16(vs, vt);
  ncarry = simde_mm_cmpeq_epi16(diff, ncarry);
  nvce = simde_mm_cmpeq_epi16(vce, zero);
  diff_zero = simde_mm_cmpeq_epi16(diff, zero);

  // Compute results for if (sign && ne):
  le_case1 = simde_mm_and_si128(diff_zero, ncarry);
  le_case1 = simde_mm_and_si128(nvce, le_case1);
  le_case2 = simde_mm_or_si128(diff_zero, ncarry);
  le_case2 = simde_mm_and_si128(vce, le_case2);
  le_eq = simde_mm_or_si128(le_case1, le_case2);

  // Compute results for if (!sign && ne):
  ge_eq = simde_mm_subs_epu16(vt, vs);
  ge_eq = simde_mm_cmpeq_epi16(ge_eq, zero);

  // Blend everything together. Caveat: we don't update
  // the results of ge/le if ne is false, so be careful.
  do_le = simde_mm_andnot_si128(eq, sign);
#ifdef __SSE4_1__
  *le = simde_mm_blendv_epi8(*le, le_eq, do_le);
#else
  le_eq = simde_mm_and_si128(do_le, le_eq);
  *le = simde_mm_andnot_si128(do_le, *le);
  *le = simde_mm_or_si128(le_eq, *le);
#endif

  do_ge = simde_mm_or_si128(sign, eq);
#ifdef __SSE4_1__
  *ge = simde_mm_blendv_epi8(ge_eq, *ge, do_ge);
#else
  *ge = simde_mm_and_si128(do_ge, *ge);
  ge_eq = simde_mm_andnot_si128(do_ge, ge_eq);
  *ge = simde_mm_or_si128(ge_eq, *ge);
#endif

  // Mux the result based on the value of sign.
#ifdef __SSE4_1__
  mux_mask = simde_mm_blendv_epi8(*ge, *le, sign);
#else
  do_le = simde_mm_and_si128(sign, *le);
  do_ge = simde_mm_andnot_si128(sign, *ge);
  mux_mask  = simde_mm_or_si128(do_le, do_ge);
#endif

#ifdef __SSE4_1__
  return simde_mm_blendv_epi8(vs, sign_negvt, mux_mask);
#else
  sign_negvt = simde_mm_and_si128(mux_mask, sign_negvt);
  vs = simde_mm_andnot_si128(mux_mask, vs);
  return simde_mm_or_si128(sign_negvt, vs);
#endif
}

