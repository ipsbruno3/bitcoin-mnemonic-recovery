// ===== n (ordem do grupo) em 4x64 big-endian =====
#define N0 ((ulong)0xFFFFFFFFFFFFFFFFUL)
#define N1 ((ulong)0xFFFFFFFFFFFFFFFEUL)
#define N2 ((ulong)0xBAAEDCE6AF48A03BUL)
#define N3 ((ulong)0xBFD25E8CD0364141UL)

#define PVT __private

/* ===== add/sub e mod n em 256-bit (4x64 BE) ===== */

inline void add256_be(PVT ulong r[4], const PVT ulong a[4],
                      const PVT ulong b[4], PVT int *carry) {
  ulong c = 0;
  #pragma unroll
  for (int i = 3; i >= 0; --i) {
    ulong s = a[i] + b[i], s2 = s + c;
    r[i] = s2;
    c = (s < b[i]) | (s2 < s);
  }
  *carry = (int)c;
}

inline void sub256_be(PVT ulong r[4], const PVT ulong a[4],
                      const PVT ulong b[4]) {
  ulong c = 0;
  #pragma unroll
  for (int i = 3; i >= 0; --i) {
    ulong bi = b[i] + c;
    c = (a[i] < bi);
    r[i] = a[i] - bi;
  }
}

inline int ge_n(const PVT ulong a[4]) {
  if (a[0] != N0)
    return a[0] > N0;
  if (a[1] != N1)
    return a[1] > N1;
  if (a[2] != N2)
    return a[2] > N2;
  return a[3] >= N3;
}

inline void addmod_n(PVT ulong r[4], const PVT ulong a[4],
                     const PVT ulong b[4]) {
  int carry;
  add256_be(r, a, b, &carry);

  if (carry || ge_n(r)) {
    const PVT ulong N_BE[4] = {N0, N1, N2, N3};
    sub256_be(r, r, N_BE);
  }
}


inline void hmac512_ccode_msg37(const ulong c[4], ulong M0, ulong M1, ulong M2,
                                ulong M3, ulong M4top5, ulong Hout[8]) {
  ulong inner[32], outer[32];
  inner[0] = c[0] ^ IPAD;
  inner[1] = c[1] ^ IPAD;
  inner[2] = c[2] ^ IPAD;
  inner[3] = c[3] ^ IPAD;
  outer[0] = c[0] ^ OPAD;
  outer[1] = c[1] ^ OPAD;
  outer[2] = c[2] ^ OPAD;
  outer[3] = c[3] ^ OPAD;
  #pragma unroll
  for (int i = 4; i < 16; i++) {
    inner[i] = IPAD;
    outer[i] = OPAD;
  }

  inner[16] = M0;
  inner[17] = M1;
  inner[18] = M2;
  inner[19] = M3;
  inner[20] = M4top5 | ((ulong)0x80UL << 16);
  #pragma unroll
  for (int i = 21; i < 30; i++)
    inner[i] = 0;
  inner[30] = 0;
  inner[31] = (ulong)1320;
  sha512_hash_two_blocks_message(inner, Hout);
  outer[16] = Hout[0];
  outer[17] = Hout[1];
  outer[18] = Hout[2];
  outer[19] = Hout[3];
  outer[20] = Hout[4];
  outer[21] = Hout[5];
  outer[22] = Hout[6];
  outer[23] = Hout[7];
  outer[24] = 0x8000000000000000UL;
  for (int i = 25; i < 30; i++)
    outer[i] = 0;
  outer[30] = 0;
  outer[31] = (ulong)1536;
  sha512_hash_two_blocks_message(outer, Hout);
}

inline void pack_hardened37(const ulong k[4], uint i, ulong *M0, ulong *M1,
                            ulong *M2, ulong *M3, ulong *M4t) {
  *M0 = (k[0] >> 8);
  *M1 = ((k[0] & 0xFFUL) << 56) | (k[1] >> 8);
  *M2 = ((k[1] & 0xFFUL) << 56) | (k[2] >> 8);
  *M3 = ((k[2] & 0xFFUL) << 56) | (k[3] >> 8);
  *M4t = ((k[3] & 0xFFUL) << 56) | ((ulong)((i >> 24) & 0xFF) << 48) |
         ((ulong)((i >> 16) & 0xFF) << 40) | ((ulong)((i >> 8) & 0xFF) << 32) |
         ((ulong)(i & 0xFF) << 24);
}

inline uint bswap32(uint v) {
  return (v >> 24) | ((v >> 8) & 0xFF00) | ((v << 8) & 0xFF0000) | (v << 24);
}

inline void x_le_to_u64be4(const uint x[8], ulong Xbe[4]) {
  Xbe[0] = ((ulong)x[7] << 32) | (ulong)x[6];
  Xbe[1] = ((ulong)x[5] << 32) | (ulong)x[4];
  Xbe[2] = ((ulong)x[3] << 32) | (ulong)x[2];
  Xbe[3] = ((ulong)x[1] << 32) | (ulong)x[0];
}

#define is_even32(Y) (!((Y)[0] & 1)) 

inline void pack_normal37(const uint Xle[8], const uint Yle[8], uint i,
                          ulong *M0, ulong *M1, ulong *M2, ulong *M3,
                          ulong *M4t) {
  ulong Xbe[4];
  x_le_to_u64be4(Xle, Xbe);
  ulong pfx = (is_even32(Yle) ? 0x02UL : 0x03UL) << 56;
  *M0 = pfx | (Xbe[0] >> 8);
  *M1 = ((Xbe[0] & 0xFFUL) << 56) | (Xbe[1] >> 8);
  *M2 = ((Xbe[1] & 0xFFUL) << 56) | (Xbe[2] >> 8);
  *M3 = ((Xbe[2] & 0xFFUL) << 56) | (Xbe[3] >> 8);
  *M4t = ((Xbe[3] & 0xFFUL) << 56) | ((ulong)((i >> 24) & 0xFF) << 48) |
         ((ulong)((i >> 16) & 0xFF) << 40) | ((ulong)((i >> 8) & 0xFF) << 32) |
         ((ulong)(i & 0xFF) << 24);
}


inline void be64_to_le32_8(const ulong k[4], uint outLE[8]) {
  outLE[0] = (uint)(k[3] & 0xffffffffUL);
  outLE[1] = (uint)(k[3] >> 32);
  outLE[2] = (uint)(k[2] & 0xffffffffUL);
  outLE[3] = (uint)(k[2] >> 32);
  outLE[4] = (uint)(k[1] & 0xffffffffUL);
  outLE[5] = (uint)(k[1] >> 32);
  outLE[6] = (uint)(k[0] & 0xffffffffUL);
  outLE[7] = (uint)(k[0] >> 32);
}



inline int derive_m_purposeh_0_i_pub(const ulong Iroot[8], uint purpose_u, uint index,
                                     ulong k_out[4], ulong c_out[4], uint X[8], uint Y[8],__constant const uint* NAFS) {
  ulong km[4] = {Iroot[0], Iroot[1], Iroot[2], Iroot[3]};
  ulong cm[4] = {Iroot[4], Iroot[5], Iroot[6], Iroot[7]};

  ulong M0, M1, M2, M3, M4t, I[8] = {0};
  uint purpose_h = (uint)(0x80000000u | (purpose_u & 0x7fffffffu));
  pack_hardened37(km, purpose_h, &M0, &M1, &M2, &M3, &M4t);
  hmac512_ccode_msg37(cm, M0, M1, M2, M3, M4t, I);
  ulong kp[4] = {I[0], I[1], I[2], I[3]}, cp[4] = {I[4], I[5], I[6], I[7]};
  addmod_n(kp, kp, km);
  if ((kp[0] | kp[1] | kp[2] | kp[3]) == 0UL) return 0;

  // pub m/purpose'
  uint kp_le[8];
  be64_to_le32_8(kp, kp_le);
  uint Xp0[8], Yp0[8];
  point_mul_xy(Xp0, Yp0, kp_le,NAFS);

  // m/purpose'/0 (normal)
  pack_normal37(Xp0, Yp0, 0u, &M0, &M1, &M2, &M3, &M4t);
  hmac512_ccode_msg37(cp, M0, M1, M2, M3, M4t, I);
  ulong kp_0[4] = {I[0], I[1], I[2], I[3]}, cp_0[4] = {I[4], I[5], I[6], I[7]};
  addmod_n(kp_0, kp_0, kp);
  if ((kp_0[0] | kp_0[1] | kp_0[2] | kp_0[3]) == 0UL) return 0;

  // pub m/purpose'/0
  uint kp0_le[8];
  be64_to_le32_8(kp_0, kp0_le);
  uint Xtmp[8], Ytmp[8];
  point_mul_xy(Xtmp, Ytmp, kp0_le,NAFS);

  // m/purpose'/0/index (normal)
  pack_normal37(Xtmp, Ytmp, index, &M0, &M1, &M2, &M3, &M4t);
  hmac512_ccode_msg37(cp_0, M0, M1, M2, M3, M4t, I);
  k_out[0]=I[0]; k_out[1]=I[1]; k_out[2]=I[2]; k_out[3]=I[3];
  addmod_n(k_out, k_out, kp_0);
  if ((k_out[0] | k_out[1] | k_out[2] | k_out[3]) == 0UL) return 0;
  c_out[0]=I[4]; c_out[1]=I[5]; c_out[2]=I[6]; c_out[3]=I[7];

  // pub final do filho
  uint k_le[8];
  be64_to_le32_8(k_out, k_le);
  point_mul_xy(X, Y, k_le,NAFS);

  return 1;
}



#ifndef B32SW_HARDENED
#define B32SW_HARDENED(i) ((uint)(0x80000000u | ((i) & 0x7fffffffu)))
#endif

inline int derive_m_84h_0h_0h_change_i_pub(const ulong Iroot[8],
                                           uint change, uint index,
                                           ulong k_out[4], ulong c_out[4],
                                           uint X[8], uint Y[8], __constant const uint*NAFS)
{
  // master
  ulong km[4] = {Iroot[0], Iroot[1], Iroot[2], Iroot[3]};
  ulong cm[4] = {Iroot[4], Iroot[5], Iroot[6], Iroot[7]};

  // normaliza parâmetros não-hardened
  change &= 1u;                 // 0 externo, 1 interno
  index  &= 0x7fffffffu;        // non-hardened

  // buffers comuns
  ulong M0, M1, M2, M3, M4t, I[8] = {0};

  // m/84' (hardened)
  pack_hardened37(km, B32SW_HARDENED(84u), &M0, &M1, &M2, &M3, &M4t);
  hmac512_ccode_msg37(cm, M0, M1, M2, M3, M4t, I);
  ulong k84[4]   = {I[0], I[1], I[2], I[3]};
  ulong c84[4]   = {I[4], I[5], I[6], I[7]};
  addmod_n(k84, k84, km);
  if ((k84[0]|k84[1]|k84[2]|k84[3]) == 0UL) return 0;

  // m/84'/0' (hardened)
  pack_hardened37(k84, B32SW_HARDENED(0u), &M0, &M1, &M2, &M3, &M4t);
  hmac512_ccode_msg37(c84, M0, M1, M2, M3, M4t, I);
  ulong k84_0[4] = {I[0], I[1], I[2], I[3]};
  ulong c84_0[4] = {I[4], I[5], I[6], I[7]};
  addmod_n(k84_0, k84_0, k84);
  if ((k84_0[0]|k84_0[1]|k84_0[2]|k84_0[3]) == 0UL) return 0;

  // m/84'/0'/0' (hardened)
  pack_hardened37(k84_0, B32SW_HARDENED(0u), &M0, &M1, &M2, &M3, &M4t);
  hmac512_ccode_msg37(c84_0, M0, M1, M2, M3, M4t, I);
  ulong k84_0_0[4] = {I[0], I[1], I[2], I[3]};
  ulong c84_0_0[4] = {I[4], I[5], I[6], I[7]};
  addmod_n(k84_0_0, k84_0_0, k84_0);
  if ((k84_0_0[0]|k84_0_0[1]|k84_0_0[2]|k84_0_0[3]) == 0UL) return 0;

  // pub m/84'/0'/0' (para derivação normal)
  uint kacc_le[8];
  be64_to_le32_8(k84_0_0, kacc_le);
  uint Xacc[8], Yacc[8];
  point_mul_xy(Xacc, Yacc, kacc_le, NAFS);

  // m/84'/0'/0'/change (normal)
  pack_normal37(Xacc, Yacc, change, &M0, &M1, &M2, &M3, &M4t);
  hmac512_ccode_msg37(c84_0_0, M0, M1, M2, M3, M4t, I);
  ulong kchg[4]  = {I[0], I[1], I[2], I[3]};
  ulong cchg[4]  = {I[4], I[5], I[6], I[7]};
  addmod_n(kchg, kchg, k84_0_0);
  if ((kchg[0]|kchg[1]|kchg[2]|kchg[3]) == 0UL) return 0;

  // pub m/84'/0'/0'/change
  uint kchg_le[8];
  be64_to_le32_8(kchg, kchg_le);
  uint Xchg[8], Ychg[8];
  point_mul_xy(Xchg, Ychg, kchg_le, NAFS);

  // m/84'/0'/0'/change/index (normal)
  pack_normal37(Xchg, Ychg, index, &M0, &M1, &M2, &M3, &M4t);
  hmac512_ccode_msg37(cchg, M0, M1, M2, M3, M4t, I);
  k_out[0] = I[0]; k_out[1] = I[1]; k_out[2] = I[2]; k_out[3] = I[3];
  addmod_n(k_out, k_out, kchg);
  if ((k_out[0]|k_out[1]|k_out[2]|k_out[3]) == 0UL) return 0;
  c_out[0] = I[4]; c_out[1] = I[5]; c_out[2] = I[6]; c_out[3] = I[7];

  // pub final do filho
  uint k_le[8];
  be64_to_le32_8(k_out, k_le);
  point_mul_xy(X, Y, k_le, NAFS);

  return 1;
}

