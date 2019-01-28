//
// arch/x86_64/rsp/vcr.h
//
// This file is subject to the terms and conditions defined in
// 'LICENSE', which is part of this source code package.
//

static inline __m128i rsp_vcr(__m128i vs, __m128i vt,
  __m128i zero, __m128i *ge, __m128i *le) {
  __m128i diff_sel_mask, diff_gez, diff_lez;
  __m128i sign, sign_notvt;

#ifdef INTENSE_DEBUG
  for (unsigned i = 0; i < 8; i++)
     fprintf(stderr, "VS[%d] = %d\n", i,
           reinterpret_cast<int16_t*>(&vs)[i]);

  for (unsigned i = 0; i < 8; i++)
     fprintf(stderr, "VT[%d] = %d\n", i,
           reinterpret_cast<int16_t*>(&vt)[i]);
#endif

  // sign = (vs ^ vt) < 0
  sign = simde_mm_xor_si128(vs, vt);
  sign = simde_mm_srai_epi16(sign, 15);

  // Compute le
  diff_lez = simde_mm_and_si128(vs, sign);
  diff_lez = simde_mm_add_epi16(diff_lez, vt);
  *le = simde_mm_srai_epi16(diff_lez, 15);
  
  // Compute ge
  diff_gez = simde_mm_or_si128(vs, sign);
  diff_gez = simde_mm_min_epi16(diff_gez, vt);
  *ge = simde_mm_cmpeq_epi16(diff_gez, vt);
  
  // sign_notvt = sn ? ~vt : vt
  sign_notvt = simde_mm_xor_si128(vt, sign);
   
  // Compute result:
#ifdef __SSE4_1__
  diff_sel_mask = simde_mm_blendv_epi8(*ge, *le, sign);
  return simde_mm_blendv_epi8(vs, sign_notvt, diff_sel_mask);
#else
  diff_sel_mask = simde_mm_sub_epi16(*le, *ge);
  diff_sel_mask = simde_mm_and_si128(diff_sel_mask, sign);
  diff_sel_mask = simde_mm_add_epi16(diff_sel_mask, *ge);
  
  zero = simde_mm_sub_epi16(sign_notvt, vs);
  zero = simde_mm_and_si128(zero, diff_sel_mask);
  return simde_mm_add_epi16(zero, vs);
#endif
}

