/*
 *    Optimized PBKDF2-HMAC-SHA512 for Mnemonic Generation
 *    ------------------------------------------------------
 *    This function implements PBKDF2 using HMAC-SHA512 in a highly optimized manner.
 *    It leverages precomputed HMAC masks (provided via inner_data and outer_data, which are
 *    initialized as gInnerData and gOuterData) to minimize the number of instructions required.
 *
 *    Technical Details:
 *      1. Pre-initialized HMAC strings: The input strings already include the initial HMAC masks and firsts size/padded sha512
 *         reducing the need for additional XOR operations.
 *      2. Individual SHA-512 Block Processing: Each SHA-512 block is processed separately to minimize overhead.
 *      3. Efficient Reuse of Temporary Buffers: Intermediate arrays (GU, OU, and U) are reused across the
 *         2048 iterations, thus optimizing memory usage and throughput.
 *      4. Manual Padding Setup: Padding values (e.g., inner_data[24] = 0x8000000000000000UL, inner_data[31] = 1536UL)
 *         are explicitly set to ensure proper SHA-512 block formatting.
 *
 *    Overall, this implementation achieves one of the most efficient PBKDF2 solutions available for
 *    Bitcoin mnemonic generation by significantly reducing instruction count and memory operations.
 *    https://github.com/ipsbruno
 */

__constant ulong8 SHA512_DEFAULT = (ulong8)(
  0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
  0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
  0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
  0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
);
#undef COPY_EIGHT_XOR
#undef COPY_EIGHT
#define COPY_EIGHT_XOR(dest, src) { ulong8 temp = vload8(0, dest) ^ vload8(0, src); vstore8(temp, 0, dest); }
#define COPY_EIGHT(dest, src) vstore8(vload8(0, src), 0, dest)

__constant ulong8 PBKDF_TRIMN = (ulong8)(
  0x8000000000000000UL, 0x0000000000000000UL,
  0x0000000000000000UL, 0x0000000000000000UL,
  0x0000000000000000UL, 0x0000000000000000UL,
  0x0000000000000000UL, 1536UL
);
static inline void pbkdf2_hmac_sha512_long(
    __private ulong inner_data[32],
    __private ulong outer_data[32],
    __private ulong T[8]
){
  __private ulong U[8], OU[8];
  __private ulong GU[8];
  vstore8(SHA512_DEFAULT, 0, GU);
  vstore8(SHA512_DEFAULT, 0, OU);
  sha512_process(inner_data + 0,  GU);
  sha512_process(outer_data + 0,  OU);
  COPY_EIGHT(U, GU);
  sha512_process(inner_data + 16, U);
  COPY_EIGHT(outer_data + 16, U);
  COPY_EIGHT(T, OU);
  sha512_process(outer_data + 16, T);
  COPY_EIGHT(U, T);
  vstore8(PBKDF_TRIMN, 0, inner_data + 24);
  #pragma unroll 6
  for (ushort i = 1; i < 2048; ++i) {
    COPY_EIGHT(inner_data + 16, U);
    COPY_EIGHT(U, GU);
    sha512_process(inner_data + 16, U);
    COPY_EIGHT(outer_data + 16, U);
    COPY_EIGHT(U, OU);
    sha512_process(outer_data + 16, U);
    COPY_EIGHT_XOR(T, U);
  }
}
