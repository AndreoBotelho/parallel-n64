// arch/x86_64/rsp/vmulm.h
//
// This file is subject to the terms and conditions defined in
// 'LICENSE', which is part of this source code package.
//

template <bool VMADM>
static inline __m128i rsp_vmadm_vmudm(__m128i vs, __m128i vt,
  __m128i zero, __m128i *acc_lo, __m128i *acc_md, __m128i *acc_hi) {
  __m128i lo, hi, sign, overflow_mask;

  lo = simde_mm_mullo_epi16(vs, vt); 
  hi = simde_mm_mulhi_epu16(vs, vt); 

  // What we're really want to do is unsigned vs * signed vt.
  // However, we have no such instructions to do so.
  //   
  // There's a trick to "fix" an unsigned product, though:
  // If vt was negative, take the upper 16-bits of the product
  // and subtract vs.
  sign = simde_mm_srai_epi16(vs, 15); 
  vt = simde_mm_and_si128(vt, sign);
  hi = simde_mm_sub_epi16(hi, vt); 

  // VMADM
  if (VMADM) {
    // Tricky part: start accumulate everything.
    // Get/keep the carry as we'll add it in later.
    overflow_mask = simde_mm_adds_epu16(*acc_lo, lo); 
    *acc_lo = simde_mm_add_epi16(*acc_lo, lo); 

    overflow_mask = simde_mm_cmpeq_epi16(*acc_lo, overflow_mask);
    overflow_mask = simde_mm_cmpeq_epi16(overflow_mask, zero);

    // This is REALLY clever. Since the product results from
    // two 16-bit components, one positive and one negative,
    // we don't have to worry about carrying the 1 (we can
    // only borrow) past 32-bits. So we can just add it here.
    hi = simde_mm_sub_epi16(hi, overflow_mask);

    // Check for overflow of the upper sum.
    overflow_mask = simde_mm_adds_epu16(*acc_md, hi); 
    *acc_md = simde_mm_add_epi16(*acc_md, hi); 

    overflow_mask = simde_mm_cmpeq_epi16(*acc_md, overflow_mask);
    overflow_mask = simde_mm_cmpeq_epi16(overflow_mask, zero);

    // Finish up the accumulation of the... accumulator.
    simde__m128i tmp = simde_mm_srai_epi16(hi, 15);
    *acc_hi = simde_mm_add_epi16(*acc_hi, tmp);
    *acc_hi = simde_mm_sub_epi16(*acc_hi, overflow_mask);

    return rsp_sclamp_acc_tomd(*acc_md, *acc_hi);
  }

  // VMUDM
  else {
    *acc_lo = lo;
    *acc_md = hi;
    *acc_hi = simde_mm_srai_epi16(hi, 15);

    return hi;
  }
}

