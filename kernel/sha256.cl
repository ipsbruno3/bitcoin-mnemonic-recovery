#define ROTR_256(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH_SHA256(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ_SHA256(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_SHA256(x) (ROTR_256(x, 2) ^ ROTR_256(x, 13) ^ ROTR_256(x, 22))
#define EP1_SHA256(x) (ROTR_256(x, 6) ^ ROTR_256(x, 11) ^ ROTR_256(x, 25))
#define SIG0_SHA256(x) (ROTR_256(x, 7) ^ ROTR_256(x, 18) ^ ((x) >> 3))
#define SIG1_SHA256(x) (ROTR_256(x, 17) ^ ROTR_256(x, 19) ^ ((x) >> 10))
__constant uint K_256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

uchar sha256_first_byte(ulong max, ulong min) {
  uint w[64] = {0};
  uint a, b, c, d, e, f, g, h, temp1, temp2;
  w[0] = (max >> 32) & 0xFFFFFFFF;
  w[1] = max & 0xFFFFFFFF;
  w[2] = (min >> 32) & 0xFFFFFFFF;
  w[3] = min & 0xFFFFFFFF;
  w[4] = 0x80000000;
  w[15] = 128;
#pragma unroll
  for (int i = 16; i < 64; ++i) {
    w[i] = w[i - 16] +
           ((ROTR_256(w[i - 15], 7)) ^ (ROTR_256(w[i - 15], 18)) ^
            (w[i - 15] >> 3)) +
           w[i - 7] +
           ((ROTR_256(w[i - 2], 17)) ^ (ROTR_256(w[i - 2], 19)) ^
            (w[i - 2] >> 10));
  }
  a = H0;
  b = H1;
  c = H2;
  d = H3;
  e = H4;
  f = H5;
  g = H6;
  h = H7;
#pragma unroll
  for (int i = 0; i < 63; ++i) {
    temp1 = h + ((ROTR_256(e, 6)) ^ (ROTR_256(e, 11)) ^ (ROTR_256(e, 25))) +
            ((e & f) ^ ((~e) & g)) + K_256[i] + w[i];
    temp2 = ((ROTR_256(a, 2)) ^ (ROTR_256(a, 13)) ^ (ROTR_256(a, 22))) +
            ((a & b) ^ (a & c) ^ (b & c));
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }
  temp1 = (h + ((ROTR_256(e, 6)) ^ (ROTR_256(e, 11)) ^ (ROTR_256(e, 25))) +
           ((e & f) ^ ((~e) & g)) + K_256[63] + w[63]);
  temp2 = (((ROTR_256(a, 2)) ^ (ROTR_256(a, 13)) ^ (ROTR_256(a, 22))) +
           ((a & b) ^ (a & c) ^ (b & c)));
  a = temp1 + temp2;
  return (uchar)(((H0 + a) >> 24) & 0xFF);
}


static inline bool bip39_checksum_valid_12(const uint seedNum[12]) {
    ulong a0 = 0, a1 = 0, a2 = 0;
    #pragma unroll
    for (int i = 0; i < 12; ++i) {
        ulong w = (ulong)(seedNum[i] & 0x7FFu);
        a0 = (a0 << 11) | (a1 >> (64 - 11));
        a1 = (a1 << 11) | (a2 >> (64 - 11));
        a2 = (a2 << 11) | w;
    }
    uchar actual_cs4 = (uchar)(a2 & 0xFu);
    ulong ent_lo = (a2 >> 4) | (a1 << (64 - 4));
    ulong ent_hi = (a1 >> 4) | (a0 << (64 - 4));

    uint w[64];
    #pragma unroll
    for (int i = 0; i < 64; ++i) w[i] = 0;
    w[0] = (uint)(ent_hi >> 32);
    w[1] = (uint)(ent_hi);
    w[2] = (uint)(ent_lo >> 32);
    w[3] = (uint)(ent_lo);

    w[4] = 0x80000000u;
    w[15] = 128u;
    #pragma unroll
    for (int i = 16; i < 64; ++i) {
        uint s0 = ROTR_256(w[i-15], 7) ^ ROTR_256(w[i-15], 18) ^ (w[i-15] >> 3);
        uint s1 = ROTR_256(w[i-2], 17) ^ ROTR_256(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint a = 0x6a09e667u;
    uint b = 0xbb67ae85u;
    uint c = 0x3c6ef372u;
    uint d = 0xa54ff53au;
    uint e = 0x510e527fu;
    uint f = 0x9b05688cu;
    uint g = 0x1f83d9abu;
    uint h = 0x5be0cd19u;
    #pragma unroll
    for (int i = 0; i < 64; ++i) {
        uint S1 = ROTR_256(e, 6) ^ ROTR_256(e, 11) ^ ROTR_256(e, 25);
        uint ch = (e & f) ^ ((~e) & g);
        uint temp1 = h + S1 + ch + K_256[i] + w[i];
        uint S0 = ROTR_256(a, 2) ^ ROTR_256(a, 13) ^ ROTR_256(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint temp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    a += 0x6a09e667u;
    uchar first_byte = (uchar)(a >> 24);
    uchar expected_cs4 = first_byte >> 4;
    return actual_cs4 == expected_cs4;
}
#undef H0
#undef H1
#undef H2
#undef H3
#undef H4
#undef H5
#undef H6
#undef H7
