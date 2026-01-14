/* -----------------------------------------------------------
 * b32sw_bech32.cl  —  Bech32 (P2WPKH) helpers com prefixo b32sw_
 * Não conflita com nada: funções, tipos e constantes renomeadas.
 * Entradas X/Y esperadas em LE (8×uint32) como no seu point_mul.
 * ----------------------------------------------------------- */

#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable

/* =================== Utils =================== */
static inline uint b32sw_rol32(uint x, uint n) {
  return (x << n) | (x >> (32 - n));
}
static inline uint b32sw_ror32(uint x, uint n) {
  return (x >> n) | (x << (32 - n));
}

/* LE(8x32) -> BE bytes[32] */
static inline void b32sw_u256le_to_be_bytes(  uint le[8],
                                             uchar out_be[32]) {
  for (int i = 0; i < 8; i++) {
    uint w = le[7 - i];
    out_be[4 * i + 0] = (uchar)(w >> 24);
    out_be[4 * i + 1] = (uchar)(w >> 16);
    out_be[4 * i + 2] = (uchar)(w >> 8);
    out_be[4 * i + 3] = (uchar)(w);
  }
}

/* =================== SHA-256 =================== */
typedef struct {
  uint h[8];
  uchar buf[64];
  ulong bits;
  size_t idx;
} b32sw_sha256_ctx;

static constant uint b32sw_K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

static inline uint b32sw_S0(uint x) {
  return b32sw_ror32(x, 2) ^ b32sw_ror32(x, 13) ^ b32sw_ror32(x, 22);
}
static inline uint b32sw_S1(uint x) {
  return b32sw_ror32(x, 6) ^ b32sw_ror32(x, 11) ^ b32sw_ror32(x, 25);
}
static inline uint b32sw_s0(uint x) {
  return b32sw_ror32(x, 7) ^ b32sw_ror32(x, 18) ^ (x >> 3);
}
static inline uint b32sw_s1(uint x) {
  return b32sw_ror32(x, 17) ^ b32sw_ror32(x, 19) ^ (x >> 10);
}
static inline uint b32sw_Ch(uint x, uint y, uint z) {
  return (x & y) ^ (~x & z);
}
static inline uint b32sw_Maj(uint x, uint y, uint z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

static inline void b32sw_sha256_init( b32sw_sha256_ctx *c) {
  c->h[0] = 0x6a09e667u;
  c->h[1] = 0xbb67ae85u;
  c->h[2] = 0x3c6ef372u;
  c->h[3] = 0xa54ff53au;
  c->h[4] = 0x510e527fu;
  c->h[5] = 0x9b05688cu;
  c->h[6] = 0x1f83d9abu;
  c->h[7] = 0x5be0cd19u;
  c->bits = 0;
  c->idx = 0;
}

static inline void b32sw_sha256_compress( b32sw_sha256_ctx *c,
                                           uchar *block) {
  uint w[64];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint)block[4 * i] << 24) | ((uint)block[4 * i + 1] << 16) |
           ((uint)block[4 * i + 2] << 8) | ((uint)block[4 * i + 3]);
  }
  for (int i = 16; i < 64; i++)
    w[i] = b32sw_s1(w[i - 2]) + w[i - 7] + b32sw_s0(w[i - 15]) + w[i - 16];
  uint a = c->h[0], b = c->h[1], c2 = c->h[2], d = c->h[3], e = c->h[4],
       f = c->h[5], g = c->h[6], h = c->h[7];
  for (int i = 0; i < 64; i++) {
    uint T1 = h + b32sw_S1(e) + b32sw_Ch(e, f, g) + b32sw_K256[i] + w[i];
    uint T2 = b32sw_S0(a) + b32sw_Maj(a, b, c2);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c2;
    c2 = b;
    b = a;
    a = T1 + T2;
  }
  c->h[0] += a;
  c->h[1] += b;
  c->h[2] += c2;
  c->h[3] += d;
  c->h[4] += e;
  c->h[5] += f;
  c->h[6] += g;
  c->h[7] += h;
}

static inline void b32sw_sha256_update( b32sw_sha256_ctx *c,
                                         uchar *data,
                                       size_t len) {
    uchar *p = data;
  c->bits += (ulong)len * 8;
  while (len--) {
    c->buf[c->idx++] = *p++;
    if (c->idx == 64) {
      b32sw_sha256_compress(c, c->buf);
      c->idx = 0;
    }
  }
}

static inline void b32sw_sha256_final( b32sw_sha256_ctx *c,
                                       uchar out[32]) {
  size_t i = c->idx;
  c->buf[i++] = 0x80;
  if (i > 56) {
    while (i < 64)
      c->buf[i++] = 0;
    b32sw_sha256_compress(c, c->buf);
    i = 0;
  }
  while (i < 56)
    c->buf[i++] = 0;
  ulong bits = c->bits; // big-endian
  for (int j = 7; j >= 0; j--)
    c->buf[56 + (7 - j)] = (uchar)(bits >> (j * 8));
  b32sw_sha256_compress(c, c->buf);
  for (int k = 0; k < 8; k++) {
    out[4 * k + 0] = (uchar)(c->h[k] >> 24);
    out[4 * k + 1] = (uchar)(c->h[k] >> 16);
    out[4 * k + 2] = (uchar)(c->h[k] >> 8);
    out[4 * k + 3] = (uchar)(c->h[k]);
  }
}

static inline void b32sw_sha256_once(  uchar *data, size_t len,
                                      uchar out[32]) {
  b32sw_sha256_ctx c;
  b32sw_sha256_init(&c);
  b32sw_sha256_update(&c, data, len);
  b32sw_sha256_final(&c, out);
}

/* =================== RIPEMD-160 =================== */
typedef struct {
  uint h[5];
  uchar buf[64];
  ulong bits; // little-endian bit count
  size_t idx;
} b32sw_rmd160_ctx;

static inline uint b32sw_RipF1(uint x, uint y, uint z) { return x ^ y ^ z; }
static inline uint b32sw_RipF2(uint x, uint y, uint z) {
  return (x & y) | (~x & z);
}
static inline uint b32sw_RipF3(uint x, uint y, uint z) { return (x | ~y) ^ z; }
static inline uint b32sw_RipF4(uint x, uint y, uint z) {
  return (x & z) | (y & ~z);
}
static inline uint b32sw_RipF5(uint x, uint y, uint z) { return x ^ (y | ~z); }

static constant uint b32sw_RI_r1[80] = {
    0,  1, 2,  3, 4,  5,  6, 7,  8, 9,  10, 11, 12, 13, 14, 15, 7,  4,  13, 1,
    10, 6, 15, 3, 12, 0,  9, 5,  2, 14, 11, 8,  3,  10, 14, 4,  9,  15, 8,  1,
    2,  7, 0,  6, 13, 11, 5, 12, 1, 9,  11, 10, 0,  8,  12, 4,  13, 3,  7,  15,
    14, 5, 6,  2, 4,  0,  5, 9,  7, 12, 2,  10, 14, 1,  3,  8,  11, 6,  15, 13};
static constant uint b32sw_RI_s1[80] = {
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6};
static constant uint b32sw_RI_r2[80] = {
    5,  14, 7,  0,  9,  2,  11, 4,  13, 6, 15, 8, 1,  10, 3,  12, 6, 11, 3, 7,
    0,  13, 5,  10, 14, 15, 8,  12, 4,  9, 1,  2, 15, 5,  1,  3,  7, 14, 6, 9,
    11, 8,  12, 2,  10, 0,  4,  13, 8,  6, 4,  1, 3,  11, 15, 0,  5, 12, 2, 13,
    9,  7,  10, 14, 12, 15, 10, 4,  1,  5, 8,  7, 6,  2,  13, 14, 0, 3,  9, 11};
static constant uint b32sw_RI_s2[80] = {
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11};
static constant uint b32sw_RI_K1[5] = {0x00000000u, 0x5a827999u, 0x6ed9eba1u,
                                       0x8f1bbcdcu, 0xa953fd4eu};
static constant uint b32sw_RI_K2[5] = {0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u,
                                       0x7a6d76e9u, 0x00000000u};

static inline void b32sw_rmd160_init( b32sw_rmd160_ctx *c) {
  c->h[0] = 0x67452301u;
  c->h[1] = 0xefcdab89u;
  c->h[2] = 0x98badcfeu;
  c->h[3] = 0x10325476u;
  c->h[4] = 0xc3d2e1f0u;
  c->bits = 0;
  c->idx = 0;
}

static inline void b32sw_rmd160_compress( b32sw_rmd160_ctx *c,
                                         const  uchar *block) {
  uint X[16];
  for (int i = 0; i < 16; i++) {
    X[i] = (uint)block[4 * i] | ((uint)block[4 * i + 1] << 8) |
           ((uint)block[4 * i + 2] << 16) | ((uint)block[4 * i + 3] << 24);
  }
  uint al = c->h[0], bl = c->h[1], cl = c->h[2], dl = c->h[3], el = c->h[4];
  uint ar = al, br = bl, cr = cl, dr = dl, er = el;

  for (int j = 0; j < 80; j++) {
    uint t;
    uint round = j / 16;
    if (round == 0)
      t = b32sw_rol32(al + b32sw_RipF1(bl, cl, dl) + X[b32sw_RI_r1[j]] +
                          b32sw_RI_K1[0],
                      b32sw_RI_s1[j]) +
          el;
    else if (round == 1)
      t = b32sw_rol32(al + b32sw_RipF2(bl, cl, dl) + X[b32sw_RI_r1[j]] +
                          b32sw_RI_K1[1],
                      b32sw_RI_s1[j]) +
          el;
    else if (round == 2)
      t = b32sw_rol32(al + b32sw_RipF3(bl, cl, dl) + X[b32sw_RI_r1[j]] +
                          b32sw_RI_K1[2],
                      b32sw_RI_s1[j]) +
          el;
    else if (round == 3)
      t = b32sw_rol32(al + b32sw_RipF4(bl, cl, dl) + X[b32sw_RI_r1[j]] +
                          b32sw_RI_K1[3],
                      b32sw_RI_s1[j]) +
          el;
    else
      t = b32sw_rol32(al + b32sw_RipF5(bl, cl, dl) + X[b32sw_RI_r1[j]] +
                          b32sw_RI_K1[4],
                      b32sw_RI_s1[j]) +
          el;
    al = el;
    el = dl;
    dl = b32sw_rol32(cl, 10);
    cl = bl;
    bl = t;

    if (round == 0)
      t = b32sw_rol32(ar + b32sw_RipF5(br, cr, dr) + X[b32sw_RI_r2[j]] +
                          b32sw_RI_K2[0],
                      b32sw_RI_s2[j]) +
          er;
    else if (round == 1)
      t = b32sw_rol32(ar + b32sw_RipF4(br, cr, dr) + X[b32sw_RI_r2[j]] +
                          b32sw_RI_K2[1],
                      b32sw_RI_s2[j]) +
          er;
    else if (round == 2)
      t = b32sw_rol32(ar + b32sw_RipF3(br, cr, dr) + X[b32sw_RI_r2[j]] +
                          b32sw_RI_K2[2],
                      b32sw_RI_s2[j]) +
          er;
    else if (round == 3)
      t = b32sw_rol32(ar + b32sw_RipF2(br, cr, dr) + X[b32sw_RI_r2[j]] +
                          b32sw_RI_K2[3],
                      b32sw_RI_s2[j]) +
          er;
    else
      t = b32sw_rol32(ar + b32sw_RipF1(br, cr, dr) + X[b32sw_RI_r2[j]] +
                          b32sw_RI_K2[4],
                      b32sw_RI_s2[j]) +
          er;
    ar = er;
    er = dr;
    dr = b32sw_rol32(cr, 10);
    cr = br;
    br = t;
  }

  uint t = c->h[1] + cl + dr;
  c->h[1] = c->h[2] + dl + er;
  c->h[2] = c->h[3] + el + ar;
  c->h[3] = c->h[4] + al + br;
  c->h[4] = c->h[0] + bl + cr;
  c->h[0] = t;
}

static inline void b32sw_rmd160_update( b32sw_rmd160_ctx *c,
                                         uchar *data,
                                       size_t len) {
    uchar *p = data;
  c->bits += (ulong)len * 8;
  while (len--) {
    c->buf[c->idx++] = *p++;
    if (c->idx == 64) {
      b32sw_rmd160_compress(c, c->buf);
      c->idx = 0;
    }
  }
}

static inline void b32sw_rmd160_final( b32sw_rmd160_ctx *c,
                                       uchar out[20]) {
  size_t i = c->idx;
  c->buf[i++] = 0x80;
  if (i > 56) {
    while (i < 64)
      c->buf[i++] = 0;
    b32sw_rmd160_compress(c, c->buf);
    i = 0;
  }
  while (i < 56)
    c->buf[i++] = 0;
  ulong bits = c->bits; // little-endian length
  for (int j = 0; j < 8; j++)
    c->buf[56 + j] = (uchar)(bits >> (8 * j));
  b32sw_rmd160_compress(c, c->buf);
  for (int k = 0; k < 5; k++) {
    out[4 * k + 0] = (uchar)(c->h[k]);
    out[4 * k + 1] = (uchar)(c->h[k] >> 8);
    out[4 * k + 2] = (uchar)(c->h[k] >> 16);
    out[4 * k + 3] = (uchar)(c->h[k] >> 24);
  }
}

static inline void b32sw_hash160(  uchar *in, size_t inlen,
                                  uchar out20[20]) {
  uchar sh[32];
  b32sw_sha256_once(in, inlen, sh);
  b32sw_rmd160_ctx rm;
  b32sw_rmd160_init(&rm);
  b32sw_rmd160_update(&rm, sh, 32);
  b32sw_rmd160_final(&rm, out20);
}

/* =================== Bech32 =================== */
static constant uchar b32sw_B32[32] = {'q', 'p', 'z', 'r', 'y', '9', 'x', '8',
                                       'g', 'f', '2', 't', 'v', 'd', 'w', '0',
                                       's', '3', 'j', 'n', '5', '4', 'k', 'h',
                                       'c', 'e', '6', 'm', 'u', 'a', '7', 'l'};

static inline ulong b32sw_bech32_polymod(  uint *v, size_t len) {
  ulong chk = 1;
  const ulong gen[5] = {0x3b6a57b2UL, 0x26508e6dUL, 0x1ea119faUL, 0x3d4233ddUL,
                        0x2a1462b3UL};
  for (size_t i = 0; i < len; i++) {
    ulong b = chk >> 25;
    chk = ((chk & 0x1ffffffUL) << 5) ^ (ulong)v[i];
    for (int j = 0; j < 5; j++)
      if ((b >> j) & 1UL)
        chk ^= gen[j];
  }
  return chk;
}

static inline size_t b32sw_bech32_hrp_expand(  uchar *hrp,
                                             size_t hrp_len,
                                              uint *out) {
  size_t n = 0;
  for (size_t i = 0; i < hrp_len; i++)
    out[n++] = (uint)((hrp[i] >> 5) & 0x07);
  out[n++] = 0;
  for (size_t i = 0; i < hrp_len; i++)
    out[n++] = (uint)(hrp[i] & 0x1f);
  return n;
}

static inline void b32sw_bech32_create_checksum(  uchar *hrp,
                                                size_t hrp_len,
                                                  uint *data,
                                                size_t data_len,
                                                 uint *chkout) {
  uint tmp[128];
  size_t n = b32sw_bech32_hrp_expand(hrp, hrp_len, tmp);
  for (size_t i = 0; i < data_len; i++)
    tmp[n++] = data[i];
  for (int i = 0; i < 6; i++)
    tmp[n++] = 0;
  ulong pm = b32sw_bech32_polymod(tmp, n) ^ 1UL;
  for (int i = 0; i < 6; i++)
    chkout[i] = (uint)((pm >> (5 * (5 - i))) & 31U);
}
static inline ulong b32sw_u64_from_le8(  uchar *p) {
    return  ((ulong)p[0])
          | ((ulong)p[1] << 8)
          | ((ulong)p[2] << 16)
          | ((ulong)p[3] << 24)
          | ((ulong)p[4] << 32)
          | ((ulong)p[5] << 40)
          | ((ulong)p[6] << 48)
          | ((ulong)p[7] << 56);
}
static inline int b32sw_bech32_encode(  uchar *hrp,
                                      size_t hrp_len,
                                        uint *data,
                                      size_t data_len,  uchar *out,
                                      size_t out_sz) {
  size_t needed = hrp_len + 1 + data_len + 6 + 1;
  if (out_sz < needed)
    return 0;
  size_t p = 0;
  for (size_t i = 0; i < hrp_len; i++) {
    uchar c = hrp[i];
    if (c >= 'A' && c <= 'Z')
      c = (uchar)(c + 32);
    out[p++] = c;
  }
  out[p++] = '1';
  for (size_t i = 0; i < data_len; i++)
    out[p++] = b32sw_B32[data[i]];
  uint chk[6];
  b32sw_bech32_create_checksum(hrp, hrp_len, data, data_len, chk);
  for (int i = 0; i < 6; i++)
    out[p++] = b32sw_B32[chk[i]];
  out[p] = 0;
  return 1;
}

static inline int b32sw_convertbits_8to5(  uchar *in,
                                         size_t in_len,  uint *out,
                                         size_t *out_len, int pad) {
  uint acc = 0;
  int bits = 0;
  size_t pos = 0;
  uint maxv = 31u;
  for (size_t i = 0; i < in_len; i++) {
    uchar v = in[i];
    acc = (acc << 8) | v;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out[pos++] = (acc >> bits) & maxv;
    }
  }
  if (pad && bits)
    out[pos++] = (acc << (5 - bits)) & maxv;
  *out_len = pos;
  return 1;
}

/* =================== API pública (namespaced) =================== */

/* PubKey comprimida de X/Y (LE 8×uint32) */
static inline void b32sw_compress_pub_from_xy_le(  uint X[8],   uint Y[8],
                                                  uchar out33[33]){
    out33[0] = (uchar)((Y[0] & 1U) ? 0x03 : 0x02); // paridade de Y (LSB) define 0x02/0x03
    b32sw_u256le_to_be_bytes(X, out33+1);          // X em big-endian nos 32 bytes seguintes
}
// ---- Pipeline: de X/Y -> tag64 (sem Bech32) ----
static inline ulong b32sw_tag64_from_xy_le(  uint X[8],
                                             uint Y[8]) {
  uchar pub33[33];
  b32sw_compress_pub_from_xy_le(X, Y, pub33); // 0x02/0x03 || X (BE)
  uchar h160[20];
  b32sw_hash160(pub33, 33, h160);  // RIPEMD160(SHA256(pub33))
  return b32sw_u64_from_le8(h160); // MESMO que o Python
}
static inline int b32sw_p2wpkh_addr_from_xy_le(  uint  X[8],
                                                 uint  Y[8],
                                                 uchar *hrp, size_t hrp_len,
                                                uchar *out, size_t out_sz)
{
    /* Sanity: HRP razoável e buffer suficiente (bech32_encode confere de novo) */
    if(hrp_len == 0 || hrp_len > 83) return 0;          /* BIP-173 limita endereços a 90 chars */

    /* 1) pubkey comprimada (0x02/0x03 || X em BE) */
    uchar pub33[33];
    b32sw_compress_pub_from_xy_le(X, Y, pub33);

    /* 2) HASH160(pubkey) = RIPEMD160(SHA256(pub33)) => 20 bytes */
    uchar h160[20];
    b32sw_hash160(pub33, 33, h160);

    /* 3) Versão witness + programa convertido para base32 de 5 bits
          Para P2WPKH: versão = 0, programa = h160 (20 bytes) */
    uint   data5[1 + 40];          /* 1 para versão + até 32 símbolos do prog; sobra é barato */
    size_t prog5_len = 0;
    /* pad=1 conforme referência (encoding) */
    if(!b32sw_convertbits_8to5(h160, 20, data5 + 1, &prog5_len, 1)) return 0;

    data5[0] = 0u;                 /* witness version 0 (P2WPKH) */
    size_t data_len = 1 + prog5_len;

    /* 4) HRP em minúsculas para checksum consistente */
    uchar hrp_lc[84];
    for(size_t i=0;i<hrp_len;i++){
        uchar c = hrp[i];
        if(c >= 'A' && c <= 'Z') c = (uchar)(c + 32);
        hrp_lc[i] = c;
    }

    /* 5) Bech32 encode (não Bech32m; isso é só para v0) */
    return b32sw_bech32_encode(hrp_lc, hrp_len, data5, data_len, out, out_sz);
}
static inline int b32sw_p2wpkh_addr_bc_from_xy_le( uint X[8], uint Y[8], uchar *out, size_t out_sz) { 
  uchar hrp_bc[2] = {'b','c'}; 
  return b32sw_p2wpkh_addr_from_xy_le(X, Y, hrp_bc, 2, out, out_sz);
   }