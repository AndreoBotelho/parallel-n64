//
// arch/x86_64/rsp/vch.h
//
// This file is subject to the terms and conditions defined in
// 'LICENSE', which is part of this source code package.
//

static inline __m128i rsp_vch(__m128i vs, __m128i vt, __m128i zero,
  __m128i *ge, __m128i *le, __m128i *eq, __m128i *sign, __m128i *vce) {

  __m128i sign_negvt, vt_neg;
  __m128i diff, diff_zero, diff_sel_mask;
  __m128i diff_gez, diff_lez;

  // sign = (vs ^ vt) < 0
  *sign = simde_mm_xor_si128(vs, vt);
  *sign = simde_mm_cmplt_epi16(*sign, zero);

  // sign_negvt = sign ? -vt : vt
  sign_negvt = simde_mm_xor_si128(vt, *sign);
  sign_negvt = simde_mm_sub_epi16(sign_negvt, *sign);

  // Compute diff, diff_zero:
  diff = simde_mm_sub_epi16(vs, sign_negvt);
  diff_zero = simde_mm_cmpeq_epi16(diff, zero);

  // Compute le/ge:
  vt_neg = simde_mm_cmplt_epi16(vt, zero);
  diff_lez = simde_mm_cmpgt_epi16(diff, zero);
  diff_gez = simde_mm_or_si128(diff_lez, diff_zero);
  diff_lez = simde_mm_cmpeq_epi16(zero, diff_lez);

#ifdef __SSE4_1__
  *ge = simde_mm_blendv_epi8(diff_gez, vt_neg, *sign);
  *le = simde_mm_blendv_epi8(vt_neg, diff_lez, *sign);
#else
  *ge = simde_mm_and_si128(*sign, vt_neg);
  diff_gez = simde_mm_andnot_si128(*sign, diff_gez);
  *ge = simde_mm_or_si128(*ge, diff_gez);

  *le = simde_mm_and_si128(*sign, diff_lez);
  diff_lez = simde_mm_andnot_si128(*sign, vt_neg);
  *le = simde_mm_or_si128(*le, diff_lez);
#endif

  // Compute vce:
  *vce = simde_mm_cmpeq_epi16(diff, *sign);
  *vce = simde_mm_and_si128(*vce, *sign);

  // Compute !eq:
  *eq = simde_mm_or_si128(diff_zero, *vce);
  *eq = simde_mm_cmpeq_epi16(*eq, zero);

  // Compute result:
#ifdef __SSE4_1__
  diff_sel_mask = simde_mm_blendv_epi8(*ge, *le, *sign);
  return simde_mm_blendv_epi8(vs, sign_negvt, diff_sel_mask);
#else
  diff_lez = simde_mm_and_si128(*sign, *le);
  diff_gez = simde_mm_andnot_si128(*sign, *ge);
  diff_sel_mask = simde_mm_or_si128(diff_lez, diff_gez);

  diff_lez = simde_mm_and_si128(diff_sel_mask, sign_negvt);
  diff_gez = simde_mm_andnot_si128(diff_sel_mask, vs);
  return simde_mm_or_si128(diff_lez, diff_gez);
#endif
}

