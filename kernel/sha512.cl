/*
 *    Custom SHA-512 Implementation for Bitcoin
 *    -------------------------------------------
 *    This is a highly optimized, custom implementation of the SHA-512 algorithm.
 *    It draws upon techniques from projects such as John the Ripper, Hashcat, and various
 *    Bitcracking-ng initiatives, and is designed to maximize performance while minimizing memory overhead.
 *
 *    Technical Optimizations:
 *      1. Uses 64-bit words (ulongs) to process data in 64-bit blocks, ensuring efficient memory usage.
 *      2. Implements a manual right-rotation (RoR) routine, reducing the number of instructions compared
 *         to conventional loop-based rotations (only H/D increments).
 *      3. Fully unrolls the processing loop (manual loop unrolling), employing a vertical rotation algorithm
 *         to eliminate the overhead associated with incremental for-loops and conditionals.
 *      4. Leverages the native OpenCL "bitselect" intrinsic to accelerate bit-level operations for enhanced performance.
 *      5. Directly utilizes the original message words (indices 0–15) to avoid redundant computation during
 *         the message schedule expansion (W0–W16).
 *      6. The design is open to further optimizations and the integration of additional intrinsics as new opportunities arise.
 *
 *    This implementation efficiently processes two 1024-bit blocks and represents the most efficient
 *    SHA-512 solution developed.
 *    https://github.com/ipsbrunoreserva
 *
 * Reference:
 * https://github.com/brichard19/core-decrypt/blob/7b0ea520372a7d0cc728d71e5a01572f09e7e29e/src/core-decrypt.cl
 * https://github.com/LIMXTEC/Xevan-GPU-Miner/blob/2994cf62171073099fab94babf1a75535c5be3fc/kernel/sha2big.cl#L46
 */


#define INIT_SHA512(a)                                                         \
  (a)[0] = 0x6a09e667f3bcc908UL;                                               \
  (a)[1] = 0xbb67ae8584caa73bUL;                                               \
  (a)[2] = 0x3c6ef372fe94f82bUL;                                               \
  (a)[3] = 0xa54ff53a5f1d36f1UL;                                               \
  (a)[4] = 0x510e527fade682d1UL;                                               \
  (a)[5] = 0x9b05688c2b3e6c1fUL;                                               \
  (a)[6] = 0x1f83d9abfb41bd6bUL;                                               \
  (a)[7] = 0x5be0cd19137e2179UL;

#define rotr64(a, n) (rotate((a), (64ul - n)))

inline ulong L0(ulong x) {
  return rotr64(x, 1ul) ^ rotr64(x, 8ul) ^ (x >> 7ul);
}

inline ulong L1(ulong x) {
  return rotr64(x, 19ul) ^ rotr64(x, 61ul) ^ (x >> 6ul);
}

#define SHA512_S0(x) (rotr64(x, 28ul) ^ rotr64(x, 34ul) ^ rotr64(x, 39ul))
#define SHA512_S1(x) (rotr64(x, 14ul) ^ rotr64(x, 18ul) ^ rotr64(x, 41ul))

#define F1(x, y, z) (bitselect(z, y, x))
#define F0(x, y, z) 

static inline ulong RoR(ulong a, ulong b, ulong c, ulong *d,
                       ulong e, ulong f, ulong g, ulong *h,
                       ulong x, ulong K, ulong bc_prev)
{
    ulong ab_current = a&b;
    ulong t1 = *h + SHA512_S1(e) + F1(e, f, g) + x + K;
    ulong maj = SHA512_S0(a) + (ab_current ^ (a & c) ^ bc_prev);  // usa bc_prev em vez de (b & c)
    *d += t1;
    *h = t1 + maj;
    return ab_current;
}


void sha512_process(ulong *message, ulong *H) {
  __private ulong A0 = H[0], A1 = H[1], A2 = H[2], A3 = H[3], A4 = H[4],
                  A5 = H[5], A6 = H[6], A7 = H[7];

  __private ulong W16 =
      (message[0] + L0(message[1]) + message[9] + L1(message[14]));
  __private ulong W17 =
      (message[1] + L0(message[2]) + message[10] + L1(message[15]));
  __private ulong W18 = (message[2] + L0(message[3]) + message[11] + L1(W16));
  __private ulong W19 = (message[3] + L0(message[4]) + message[12] + L1(W17));
  __private ulong W20 = (message[4] + L0(message[5]) + message[13] + L1(W18));
  __private ulong W21 = (message[5] + L0(message[6]) + message[14] + L1(W19));
  __private ulong W22 = message[6] + L0(message[7]) + message[15] + L1(W20);
  __private ulong W23 = message[7] + L0(message[8]) + W16 + L1(W21);
  __private ulong W24 = message[8] + L0(message[9]) + W17 + L1(W22);
  __private ulong W25 = message[9] + L0(message[10]) + W18 + L1(W23);
  __private ulong W26 = message[10] + L0(message[11]) + W19 + L1(W24);
  __private ulong W27 = message[11] + L0(message[12]) + W20 + L1(W25);
  __private ulong W28 = message[12] + L0(message[13]) + W21 + L1(W26);
  __private ulong W29 = message[13] + L0(message[14]) + W22 + L1(W27);
  __private ulong W30 = message[14] + L0(message[15]) + W23 + L1(W28);
  __private ulong W31 = message[15] + L0(W16) + W24 + L1(W29);

  __private ulong W32 = W16 + L0(W17) + W25 + L1(W30);
  __private ulong W33 = W17 + L0(W18) + W26 + L1(W31);
  __private ulong W34 = W18 + L0(W19) + W27 + L1(W32);
  __private ulong W35 = W19 + L0(W20) + W28 + L1(W33);
  __private ulong W36 = W20 + L0(W21) + W29 + L1(W34);
  __private ulong W37 = W21 + L0(W22) + W30 + L1(W35);
  __private ulong W38 = W22 + L0(W23) + W31 + L1(W36);
  __private ulong W39 = W23 + L0(W24) + W32 + L1(W37);
  __private ulong W40 = W24 + L0(W25) + W33 + L1(W38);
  __private ulong W41 = W25 + L0(W26) + W34 + L1(W39);
  __private ulong W42 = W26 + L0(W27) + W35 + L1(W40);
  __private ulong W43 = W27 + L0(W28) + W36 + L1(W41);
  __private ulong W44 = W28 + L0(W29) + W37 + L1(W42);
  __private ulong W45 = W29 + L0(W30) + W38 + L1(W43);
  __private ulong W46 = W30 + L0(W31) + W39 + L1(W44);
  __private ulong W47 = W31 + L0(W32) + W40 + L1(W45);
  __private ulong W48 = W32 + L0(W33) + W41 + L1(W46);
  __private ulong W49 = W33 + L0(W34) + W42 + L1(W47);
  __private ulong W50 = W34 + L0(W35) + W43 + L1(W48);
  __private ulong W51 = W35 + L0(W36) + W44 + L1(W49);
  __private ulong W52 = W36 + L0(W37) + W45 + L1(W50);
  __private ulong W53 = W37 + L0(W38) + W46 + L1(W51);
  __private ulong W54 = W38 + L0(W39) + W47 + L1(W52);
  __private ulong W55 = W39 + L0(W40) + W48 + L1(W53);
  __private ulong W56 = W40 + L0(W41) + W49 + L1(W54);
  __private ulong W57 = W41 + L0(W42) + W50 + L1(W55);
  __private ulong W58 = W42 + L0(W43) + W51 + L1(W56);
  __private ulong W59 = W43 + L0(W44) + W52 + L1(W57);
  __private ulong W60 = W44 + L0(W45) + W53 + L1(W58);
  __private ulong W61 = W45 + L0(W46) + W54 + L1(W59);
  __private ulong W62 = W46 + L0(W47) + W55 + L1(W60);
  __private ulong W63 = W47 + L0(W48) + W56 + L1(W61);
  __private ulong W64 = W48 + L0(W49) + W57 + L1(W62);
  __private ulong W65 = W49 + L0(W50) + W58 + L1(W63);
  __private ulong W66 = W50 + L0(W51) + W59 + L1(W64);
  __private ulong W67 = W51 + L0(W52) + W60 + L1(W65);
  __private ulong W68 = W52 + L0(W53) + W61 + L1(W66);
  __private ulong W69 = W53 + L0(W54) + W62 + L1(W67);
  __private ulong W70 = W54 + L0(W55) + W63 + L1(W68);
  __private ulong W71 = W55 + L0(W56) + W64 + L1(W69);
  __private ulong W72 = W56 + L0(W57) + W65 + L1(W70);
  __private ulong W73 = W57 + L0(W58) + W66 + L1(W71);
  __private ulong W74 = W58 + L0(W59) + W67 + L1(W72);
  __private ulong W75 = W59 + L0(W60) + W68 + L1(W73);
  __private ulong W76 = W60 + L0(W61) + W69 + L1(W74);
  __private ulong W77 = W61 + L0(W62) + W70 + L1(W75);
  __private ulong W78 = W62 + L0(W63) + W71 + L1(W76);
  __private ulong W79 = W63 + L0(W64) + W72 + L1(W77);

    ulong bc = A1 & A2;
    ulong ab = RoR(A0, A1, A2, &A3, A4, A5, A6, &A7, message[0],  0x428a2f98d728ae22UL, bc);
    ab = RoR(A7, A0, A1, &A2, A3, A4, A5, &A6, message[1],  0x7137449123ef65cdUL, ab);
    ab = RoR(A6, A7, A0, &A1, A2, A3, A4, &A5, message[2],  0xb5c0fbcfec4d3b2fUL, ab);
    ab = RoR(A5, A6, A7, &A0, A1, A2, A3, &A4, message[3],  0xe9b5dba58189dbbcUL, ab);
    ab = RoR(A4, A5, A6, &A7, A0, A1, A2, &A3, message[4],  0x3956c25bf348b538UL, ab);
    ab = RoR(A3, A4, A5, &A6, A7, A0, A1, &A2, message[5],  0x59f111f1b605d019UL, ab);
    ab = RoR(A2, A3, A4, &A5, A6, A7, A0, &A1, message[6],  0x923f82a4af194f9bUL, ab);
    ab = RoR(A1, A2, A3, &A4, A5, A6, A7, &A0, message[7],  0xab1c5ed5da6d8118UL, ab);
    ab = RoR(A0, A1, A2, &A3, A4, A5, A6, &A7, message[8],  0xd807aa98a3030242UL, ab);
    ab = RoR(A7, A0, A1, &A2, A3, A4, A5, &A6, message[9],  0x12835b0145706fbeUL, ab);
    ab = RoR(A6, A7, A0, &A1, A2, A3, A4, &A5, message[10], 0x243185be4ee4b28cUL, ab);
    ab = RoR(A5, A6, A7, &A0, A1, A2, A3, &A4, message[11], 0x550c7dc3d5ffb4e2UL, ab);
    ab = RoR(A4, A5, A6, &A7, A0, A1, A2, &A3, message[12], 0x72be5d74f27b896fUL, ab);
    ab = RoR(A3, A4, A5, &A6, A7, A0, A1, &A2, message[13], 0x80deb1fe3b1696b1UL, ab);
    ab = RoR(A2, A3, A4, &A5, A6, A7, A0, &A1, message[14], 0x9bdc06a725c71235UL, ab);
    ab = RoR(A1, A2, A3, &A4, A5, A6, A7, &A0, message[15], 0xc19bf174cf692694UL, ab);
    ab = RoR(A0, A1, A2, &A3, A4, A5, A6, &A7, W16, 0xe49b69c19ef14ad2UL, ab);
    ab = RoR(A7, A0, A1, &A2, A3, A4, A5, &A6, W17, 0xefbe4786384f25e3UL, ab);
    ab = RoR(A6, A7, A0, &A1, A2, A3, A4, &A5, W18, 0x0fc19dc68b8cd5b5UL, ab);
    ab = RoR(A5, A6, A7, &A0, A1, A2, A3, &A4, W19, 0x240ca1cc77ac9c65UL, ab);
    ab = RoR(A4, A5, A6, &A7, A0, A1, A2, &A3, W20, 0x2de92c6f592b0275UL, ab);
    ab = RoR(A3, A4, A5, &A6, A7, A0, A1, &A2, W21, 0x4a7484aa6ea6e483UL, ab);
    ab = RoR(A2, A3, A4, &A5, A6, A7, A0, &A1, W22, 0x5cb0a9dcbd41fbd4UL, ab);
    ab = RoR(A1, A2, A3, &A4, A5, A6, A7, &A0, W23, 0x76f988da831153b5UL, ab);
    ab = RoR(A0, A1, A2, &A3, A4, A5, A6, &A7, W24, 0x983e5152ee66dfabUL, ab);
    ab = RoR(A7, A0, A1, &A2, A3, A4, A5, &A6, W25, 0xa831c66d2db43210UL, ab);
    ab = RoR(A6, A7, A0, &A1, A2, A3, A4, &A5, W26, 0xb00327c898fb213fUL, ab);
    ab = RoR(A5, A6, A7, &A0, A1, A2, A3, &A4, W27, 0xbf597fc7beef0ee4UL, ab);
    ab = RoR(A4, A5, A6, &A7, A0, A1, A2, &A3, W28, 0xc6e00bf33da88fc2UL, ab);
    ab = RoR(A3, A4, A5, &A6, A7, A0, A1, &A2, W29, 0xd5a79147930aa725UL, ab);
    ab = RoR(A2, A3, A4, &A5, A6, A7, A0, &A1, W30, 0x06ca6351e003826fUL, ab);
    ab = RoR(A1, A2, A3, &A4, A5, A6, A7, &A0, W31, 0x142929670a0e6e70UL, ab);
    ab = RoR(A0, A1, A2, &A3, A4, A5, A6, &A7, W32, 0x27b70a8546d22ffcUL, ab);
    ab = RoR(A7, A0, A1, &A2, A3, A4, A5, &A6, W33, 0x2e1b21385c26c926UL, ab);
    ab = RoR(A6, A7, A0, &A1, A2, A3, A4, &A5, W34, 0x4d2c6dfc5ac42aedUL, ab);
    ab = RoR(A5, A6, A7, &A0, A1, A2, A3, &A4, W35, 0x53380d139d95b3dfUL, ab);
    ab = RoR(A4, A5, A6, &A7, A0, A1, A2, &A3, W36, 0x650a73548baf63deUL, ab);
    ab = RoR(A3, A4, A5, &A6, A7, A0, A1, &A2, W37, 0x766a0abb3c77b2a8UL, ab);
    ab = RoR(A2, A3, A4, &A5, A6, A7, A0, &A1, W38, 0x81c2c92e47edaee6UL, ab);
    ab = RoR(A1, A2, A3, &A4, A5, A6, A7, &A0, W39, 0x92722c851482353bUL, ab);
    ab = RoR(A0, A1, A2, &A3, A4, A5, A6, &A7, W40, 0xa2bfe8a14cf10364UL, ab);
    ab = RoR(A7, A0, A1, &A2, A3, A4, A5, &A6, W41, 0xa81a664bbc423001UL, ab);
    ab = RoR(A6, A7, A0, &A1, A2, A3, A4, &A5, W42, 0xc24b8b70d0f89791UL, ab);
    ab = RoR(A5, A6, A7, &A0, A1, A2, A3, &A4, W43, 0xc76c51a30654be30UL, ab);
    ab = RoR(A4, A5, A6, &A7, A0, A1, A2, &A3, W44, 0xd192e819d6ef5218UL, ab);
    ab = RoR(A3, A4, A5, &A6, A7, A0, A1, &A2, W45, 0xd69906245565a910UL, ab);
    ab = RoR(A2, A3, A4, &A5, A6, A7, A0, &A1, W46, 0xf40e35855771202aUL, ab);
    ab = RoR(A1, A2, A3, &A4, A5, A6, A7, &A0, W47, 0x106aa07032bbd1b8UL, ab);
    ab = RoR(A0, A1, A2, &A3, A4, A5, A6, &A7, W48, 0x19a4c116b8d2d0c8UL, ab);
    ab = RoR(A7, A0, A1, &A2, A3, A4, A5, &A6, W49, 0x1e376c085141ab53UL, ab);
    ab = RoR(A6, A7, A0, &A1, A2, A3, A4, &A5, W50, 0x2748774cdf8eeb99UL, ab);
    ab = RoR(A5, A6, A7, &A0, A1, A2, A3, &A4, W51, 0x34b0bcb5e19b48a8UL, ab);
    ab = RoR(A4, A5, A6, &A7, A0, A1, A2, &A3, W52, 0x391c0cb3c5c95a63UL, ab);
    ab = RoR(A3, A4, A5, &A6, A7, A0, A1, &A2, W53, 0x4ed8aa4ae3418acbUL, ab);
    ab = RoR(A2, A3, A4, &A5, A6, A7, A0, &A1, W54, 0x5b9cca4f7763e373UL, ab);
    ab = RoR(A1, A2, A3, &A4, A5, A6, A7, &A0, W55, 0x682e6ff3d6b2b8a3UL, ab);
    ab = RoR(A0, A1, A2, &A3, A4, A5, A6, &A7, W56, 0x748f82ee5defb2fcUL, ab);
    ab = RoR(A7, A0, A1, &A2, A3, A4, A5, &A6, W57, 0x78a5636f43172f60UL, ab);
    ab = RoR(A6, A7, A0, &A1, A2, A3, A4, &A5, W58, 0x84c87814a1f0ab72UL, ab);
    ab = RoR(A5, A6, A7, &A0, A1, A2, A3, &A4, W59, 0x8cc702081a6439ecUL, ab);
    ab = RoR(A4, A5, A6, &A7, A0, A1, A2, &A3, W60, 0x90befffa23631e28UL, ab);
    ab = RoR(A3, A4, A5, &A6, A7, A0, A1, &A2, W61, 0xa4506cebde82bde9UL, ab);
    ab = RoR(A2, A3, A4, &A5, A6, A7, A0, &A1, W62, 0xbef9a3f7b2c67915UL, ab);
    ab = RoR(A1, A2, A3, &A4, A5, A6, A7, &A0, W63, 0xc67178f2e372532bUL, ab);
    ab = RoR(A0, A1, A2, &A3, A4, A5, A6, &A7, W64, 0xca273eceea26619cUL, ab);
    ab = RoR(A7, A0, A1, &A2, A3, A4, A5, &A6, W65, 0xd186b8c721c0c207UL, ab);
    ab = RoR(A6, A7, A0, &A1, A2, A3, A4, &A5, W66, 0xeada7dd6cde0eb1eUL, ab);
    ab = RoR(A5, A6, A7, &A0, A1, A2, A3, &A4, W67, 0xf57d4f7fee6ed178UL, ab);
    ab = RoR(A4, A5, A6, &A7, A0, A1, A2, &A3, W68, 0x06f067aa72176fbaUL, ab);
    ab = RoR(A3, A4, A5, &A6, A7, A0, A1, &A2, W69, 0xa637dc5a2c898a6UL, ab);
    ab = RoR(A2, A3, A4, &A5, A6, A7, A0, &A1, W70, 0x113f9804bef90daeUL, ab);
    ab = RoR(A1, A2, A3, &A4, A5, A6, A7, &A0, W71, 0x1b710b35131c471bUL, ab);
    ab = RoR(A0, A1, A2, &A3, A4, A5, A6, &A7, W72, 0x28db77f523047d84UL, ab);
    ab = RoR(A7, A0, A1, &A2, A3, A4, A5, &A6, W73, 0x32caab7b40c72493UL, ab);
    ab = RoR(A6, A7, A0, &A1, A2, A3, A4, &A5, W74, 0x3c9ebe0a15c9bebcUL, ab);
    ab = RoR(A5, A6, A7, &A0, A1, A2, A3, &A4, W75, 0x431d67c49c100d4cUL, ab);
    ab = RoR(A4, A5, A6, &A7, A0, A1, A2, &A3, W76, 0x4cc5d4becb3e42b6UL, ab);
    ab = RoR(A3, A4, A5, &A6, A7, A0, A1, &A2, W77, 0x597f299cfc657e2aUL, ab);
    ab = RoR(A2, A3, A4, &A5, A6, A7, A0, &A1, W78, 0x5fcb6fab3ad6faecUL, ab);
    RoR(A1, A2, A3, &A4, A5, A6, A7, &A0, W79, 0x6c44198c4a475817UL, ab);
  H[0] += A0;
  H[1] += A1;
  H[2] += A2;
  H[3] += A3;
  H[4] += A4;
  H[5] += A5;
  H[6] += A6;
  H[7] += A7;
}

void sha512_hash_two_blocks_message(ulong *message, ulong *H) {
  INIT_SHA512(H);
  sha512_process(message, H);
  sha512_process(message + 16, H);
}

