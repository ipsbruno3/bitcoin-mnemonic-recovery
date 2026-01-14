

#define WNAF_MASK  ((1u << WNAF_W) - 1u)   
#define WNAF_HALF  (1u << (WNAF_W - 1u)) 

#define SECP256K1_B 7

#define SECP256K1_P0 0xfffffc2f
#define SECP256K1_P1 0xfffffffe
#define SECP256K1_P2 0xffffffff
#define SECP256K1_P3 0xffffffff
#define SECP256K1_P4 0xffffffff
#define SECP256K1_P5 0xffffffff
#define SECP256K1_P6 0xffffffff
#define SECP256K1_P7 0xffffffff

#define SECPK256K_VALUES                                                       \
  SECP256K1_P0, SECP256K1_P1, SECP256K1_P2, SECP256K1_P3, SECP256K1_P4,        \
      SECP256K1_P5, SECP256K1_P6, SECP256K1_P7

#define is_zero(n)                                                             \
  (!n[8] && !n[7] && !n[6] && !n[5] && !n[4] && !n[3] && !n[2] && !n[1] &&     \
   !n[0])

#define shift_first(aElem, lastValue)                                          \
  (aElem)[0] = (aElem)[0] >> 1 | (aElem)[1] << 31;                             \
  (aElem)[1] = (aElem)[1] >> 1 | (aElem)[2] << 31;                             \
  (aElem)[2] = (aElem)[2] >> 1 | (aElem)[3] << 31;                             \
  (aElem)[3] = (aElem)[3] >> 1 | (aElem)[4] << 31;                             \
  (aElem)[4] = (aElem)[4] >> 1 | (aElem)[5] << 31;                             \
  (aElem)[5] = (aElem)[5] >> 1 | (aElem)[6] << 31;                             \
  (aElem)[6] = (aElem)[6] >> 1 | (aElem)[7] << 31;                             \
  (aElem)[7] = lastValue;

#define copy_eight(a, b)                                                       \
  (a)[0] = (b)[0], (a)[1] = (b)[1], (a)[2] = (b)[2], (a)[3] = (b)[3],          \
  (a)[4] = (b)[4], (a)[5] = (b)[5], (a)[6] = (b)[6], (a)[7] = (b)[7];

#define is_even(x) !((x)[0] & 1)
static inline uint sub(uint *r,
                       const uint *a,
                       const uint *b)
{
    ulong tmp, ai, ri;
    uint borrow = 0;

    tmp=(ulong)b[0]+borrow; ai=a[0]; ri=ai-tmp; r[0]=(uint)ri; borrow=(ai<tmp);
    tmp=(ulong)b[1]+borrow; ai=a[1]; ri=ai-tmp; r[1]=(uint)ri; borrow=(ai<tmp);
    tmp=(ulong)b[2]+borrow; ai=a[2]; ri=ai-tmp; r[2]=(uint)ri; borrow=(ai<tmp);
    tmp=(ulong)b[3]+borrow; ai=a[3]; ri=ai-tmp; r[3]=(uint)ri; borrow=(ai<tmp);
    tmp=(ulong)b[4]+borrow; ai=a[4]; ri=ai-tmp; r[4]=(uint)ri; borrow=(ai<tmp);
    tmp=(ulong)b[5]+borrow; ai=a[5]; ri=ai-tmp; r[5]=(uint)ri; borrow=(ai<tmp);
    tmp=(ulong)b[6]+borrow; ai=a[6]; ri=ai-tmp; r[6]=(uint)ri; borrow=(ai<tmp);
    tmp=(ulong)b[7]+borrow; ai=a[7]; ri=ai-tmp; r[7]=(uint)ri; borrow=(ai<tmp);

    return borrow;
}



uint add(uint *r, const uint *a, const uint *b) {
  uint c = 0, t;
  t = a[0] + b[0] + c;
  c = (t != a[0]) ? (t < a[0]) : c;
  r[0] = t;
  t = a[1] + b[1] + c;
  c = (t != a[1]) ? (t < a[1]) : c;
  r[1] = t;
  t = a[2] + b[2] + c;
  c = (t != a[2]) ? (t < a[2]) : c;
  r[2] = t;
  t = a[3] + b[3] + c;
  c = (t != a[3]) ? (t < a[3]) : c;
  r[3] = t;
  t = a[4] + b[4] + c;
  c = (t != a[4]) ? (t < a[4]) : c;
  r[4] = t;
  t = a[5] + b[5] + c;
  c = (t != a[5]) ? (t < a[5]) : c;
  r[5] = t;
  t = a[6] + b[6] + c;
  c = (t != a[6]) ? (t < a[6]) : c;
  r[6] = t;
  t = a[7] + b[7] + c;
  c = (t != a[7]) ? (t < a[7]) : c;
  r[7] = t;
  return c;
}

inline bool is_less(const uint *a, const uint *b) {
  #pragma unroll
  for (int i = 7; i >= 0; i--) {
    if (a[i] < b[i])
      return true;
    if (a[i] > b[i])
      return false;
  }
  return false;
}
inline void shift_and_add(uint *x, uint *y, const uint *p) {
  shift_first(x, x[7] >> 1);
  uint c = 0;
  if (!is_even(y)) {
    c = add(y, y, p);
  }
  shift_first(y, y[7] >> 1 | c << 31);
}

inline void sub_and_shift(uint *x, const uint *y, uint *z, const uint *w,
                          const uint *p) {
  sub(x, x, y);
  shift_first(x, x[7] >> 1);
  if (is_less(z, w)) {
    add(z, z, p);
  }
  sub(z, z, w);

  if (!is_even(z)) {
    uint c = add(z, z, p);
    shift_first(z, z[7] >> 1 | c << 31);
  } else {
    shift_first(z, z[7] >> 1);
  }
}

inline bool is_greater(const uint *a, const uint *b) {
  #pragma unroll
  for (int i = 7; i >= 0; i--) {
    if (a[i] != b[i])
      return (a[i] > b[i]);
  }
  return false;
}

inline bool arrays_equal(const uint *a, const uint *b) {
  #pragma unroll
  for (int i = 0; i < 8; i++) {
    if (a[i] != b[i])
      return false;
  }
  return true;
}
inline void sub_mod(uint *r, const uint *a, const uint *b) {
  const uint c = sub(r, a, b);
  if (c) {
    uint t[8] = {SECPK256K_VALUES};
    add(r, r, t);
  }
}

inline void add_mod(uint *r, const uint *a, const uint *b) {
  uint t[8] = {SECPK256K_VALUES};
  if (!add(r, a, b)) {
    #pragma unroll
    for (int i = 7; i >= 0; i--) {
      if (r[i] < t[i]) {
        return;
      }
      if (r[i] > t[i]) {
        break;
      }
    }
  }
  sub(r, r, t);
}

void mul_mod(uint *r, const uint *a, const uint *b) {
  uint t[16] = {0};
  uint t0 = 0;
  uint t1 = 0;
  uint c = 0;
  #pragma unroll
  for (uint i = 0; i < 8; i++) {
    #pragma unroll
    for (uint j = 0; j <= i; j++) {
      ulong p = ((ulong)a[j]) * b[i - j];
      ulong d = ((ulong)t1) << 32 | t0;

      d += p;
      t0 = (uint)d;
      t1 = d >> 32;
      c += d < p;
    }

    t[i] = t0;
    t0 = t1;
    t1 = c;
    c = 0;
  }
#pragma unroll
  for (uint i = 8; i < 15; i++) {
    #pragma unroll
    for (uint j = i - 7; j < 8; j++) {
      ulong p = ((ulong)a[j]) * b[i - j];
      ulong d = ((ulong)t1) << 32 | t0;
      d += p;
      t0 = (uint)d;
      t1 = d >> 32;
      c += d < p;
    }
    t[i] = t0;
    t0 = t1;
    t1 = c;
    c = 0;
  }

  t[15] = t0;
  uint tmp[16] = {0};
  #pragma unroll
  for (uint i = 0, j = 8; i < 8; i++, j++) {
    ulong p = ((ulong)0x03d1) * t[j] + c;
    tmp[i] = (uint)p;
    c = p >> 32;
  }
  tmp[8] = c;
  c = add(tmp + 1, tmp + 1, t + 8);
  tmp[9] = c;
  c = add(r, t, tmp);
  uint c2 = 0;
  #pragma unroll
  for (uint i = 0, j = 8; i < 8; i++, j++) {
    ulong p = ((ulong)0x3d1) * tmp[j] + c2;
    t[i] = (uint)p;
    c2 = p >> 32;
  }

  t[8] = c2;
  c2 = add(t + 1, t + 1, tmp + 8);
  t[9] = c2;

  uint h[8] = {SECPK256K_VALUES};
  #pragma unroll
  for (uint i = c + add(r, r, t); i > 0; i--) {
    sub(r, r, h);
  }
  #pragma unroll
  for (int i = 7; i >= 0; i--) {
    if (r[i] < h[i])
      break;
    if (r[i] > h[i]) {
      sub(r, r, h);
      break;
    }
  }
}

void inv_mod(uint *a) {
  uint t0[8] = {a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]};
  uint p[8] = {SECPK256K_VALUES};
  uint t1[8] = {SECPK256K_VALUES};
  uint t2[8] = {0x00000001, 0, 0, 0, 0, 0, 0, 0};
  uint t3[8] = {0};

  while (!arrays_equal(t0, t1)) {
    if (is_even(t0)) {
      shift_and_add(t0, t2, p);
    } else if (is_even(t1)) {
      shift_and_add(t1, t3, p);
    } else {
      if (is_greater(t0, t1)) {
        sub_and_shift(t0, t1, t2, t3, p);
      } else {
        sub_and_shift(t1, t0, t3, t2, p);
      }
    }
  }
  copy_eight(a, t2);
}

void point_double(uint *x, uint *y, uint *z) {

  uint t1[8];
  uint t2[8];
  uint t3[8] = {z[0], z[1], z[2], z[3], z[4], z[5], z[6], z[7]};
  uint t4[8];
  uint t5[8];
  uint t6[8];
  copy_eight(t2, y);
  mul_mod(t4, x, x);
  mul_mod(t5, y, y);
  mul_mod(t3, y, z);
  mul_mod(t1, x, t5);
  mul_mod(t5, t5, t5);
  add_mod(t2, t4, t4);
  add_mod(t4, t4, t2);
  uint c = 0;
  if (t4[0] & 1) {
    uint t[8] = {SECPK256K_VALUES};
    c = add(t4, t4, t);
  }
  shift_first(t4, t4[7] >> 1 | c << 31);
  mul_mod(t6, t4, t4);
  add_mod(t2, t1, t1);
  sub_mod(t6, t6, t2);
  sub_mod(t1, t1, t6);
  mul_mod(t4, t4, t1);
  sub_mod(t1, t4, t5);

  copy_eight(x, t6);
  copy_eight(y, t1);
  copy_eight(z, t3);
}

void point_add(uint *x1, uint *y1, uint *z1,const __constant unsigned int *x2,
              const __constant unsigned int *y2) // z2 = 1
{

  uint t1[8];
  uint t2[8];
  uint t3[8];
  uint t4[8];
  uint t5[8];
  uint t6[8];
  uint t7[8];
  uint t8[8];
  uint t9[8];

  copy_eight(t1, x1);
  copy_eight(t2, y1);
  copy_eight(t3, z1);
  copy_eight(t4, x2);
  copy_eight(t5, y2);

  mul_mod(t6, t3, t3); // t6 = t3^2

  mul_mod(t7, t6, t3); // t7 = t6*t3
  mul_mod(t6, t6, t4); // t6 = t6*t4
  mul_mod(t7, t7, t5); // t7 = t7*t5

  sub_mod(t6, t6, t1); // t6 = t6-t1
  sub_mod(t7, t7, t2); // t7 = t7-t2

  mul_mod(t8, t3, t6); // t8 = t3*t6
  mul_mod(t4, t6, t6); // t4 = t6^2
  mul_mod(t9, t4, t6); // t9 = t4*t6
  mul_mod(t4, t4, t1); // t4 = t4*t1

  t6[7] = t4[7] << 1 | t4[6] >> 31;
  t6[6] = t4[6] << 1 | t4[5] >> 31;
  t6[5] = t4[5] << 1 | t4[4] >> 31;
  t6[4] = t4[4] << 1 | t4[3] >> 31;
  t6[3] = t4[3] << 1 | t4[2] >> 31;
  t6[2] = t4[2] << 1 | t4[1] >> 31;
  t6[1] = t4[1] << 1 | t4[0] >> 31;
  t6[0] = t4[0] << 1;

  if (t4[7] & 0x80000000) {
    uint a[8] = {0x000003d1, 1, 0, 0, 0, 0, 0, 0};
    add(t6, t6, a);
  }

  mul_mod(t5, t7, t7); // t5 = t7*t7
  sub_mod(t5, t5, t6); // t5 = t5-t6
  sub_mod(t5, t5, t9); // t5 = t5-t9
  sub_mod(t4, t4, t5); // t4 = t4-t5
  mul_mod(t4, t4, t7); // t4 = t4*t7
  mul_mod(t9, t9, t2); // t9 = t9*t2
  sub_mod(t9, t4, t9); // t9 = t4-t9

  copy_eight(x1, t5);
  copy_eight(y1, t9);
  copy_eight(z1, t8);
}

uint msb_point(uint n[9]) {
  uint msb = 0;
  #pragma unroll
  for (int i = 1; i <= 8; i++) { 
    if (n[i]) {
      msb = (9 - i) * 32 + 31 - __builtin_clz(n[i]); 
      break;
    } 
  }
  return msb;
}



inline int convert_to_window_naf(uint *naf, const uint *k) {
  int loop_start = 0;

  uint n[9] = {0, k[7], k[6], k[5], k[4], k[3], k[2], k[1], k[0]};

  uint msb = msb_point(n);
  for (int i = 0; i <= (int)msb; i++) {
    if (n[8] & 1u) {
      uint u = n[8] & WNAF_MASK;     
      int  diff = (int)u; 
      uint val = u;              

      if (u >= WNAF_HALF) {
        diff -= (1 << WNAF_W);           
        val  = ((1u << WNAF_W) + 1u) - u; 
      }
      naf[i >> 1] |= (val & 0xFFFFu) << ((i & 1) << 4);
      uint t = n[8];
      n[8] -= (uint)diff;

      uint k_idx = 8;
      while (k_idx > 0 &&
            ((diff > 0 && n[k_idx] > t) ||     
             (diff < 0 && t > n[k_idx]))) {  
        k_idx--;
        t = n[k_idx];
        n[k_idx] += (diff > 0) ? (uint)-1 : (uint)1;
      }

      loop_start = i;
    }
    for (int j = 8; j > 0; j--) {
      n[j] = (n[j] >> 1) | (n[j - 1] << 31);
    }
    n[0] >>= 1;
    if (is_zero(n)) break;
  }
  return loop_start;
}


void point_mul_xy(uint *x1, uint *y1, uint *k, __constant const uint * secpk256PreComputed) {

  uint naf[129] = {0};
  uint y[8] = {0}; 
  uint x[8] = {0};

  int loop_start = convert_to_window_naf(naf, k);

  uint multiplier = (naf[loop_start >> 1] >> ((loop_start & 1) << 4)) & 0xFFFFu;
  uint odd = multiplier & 1u;

  uint x_pos = ((multiplier - 1u + odd) >> 1) * 24u;
  uint y_pos = odd ? (x_pos + 8u) : (x_pos + 16u);

  copy_eight(x, secpk256PreComputed + x_pos);
  copy_eight(y, secpk256PreComputed + y_pos);

  uint z1[8] = {1,0,0,0,0,0,0,0};

  for (int pos = loop_start - 1; pos >= 0; pos--) {
    point_double(x, y, z1);

    multiplier = (naf[pos >> 1] >> ((pos & 1) << 4)) & 0xFFFFu;
    if (multiplier) {
      odd = multiplier & 1u;
      x_pos = ((multiplier - 1u + odd) >> 1) * 24u;
      y_pos = odd ? (x_pos + 8u) : (x_pos + 16u);
      point_add(x, y, z1, secpk256PreComputed +    x_pos, secpk256PreComputed + y_pos);
    }
  }
    inv_mod(z1);
    uint z2[8];
    mul_mod(z2, z1, z1);
    mul_mod(x, x, z2);
    mul_mod(z1, z2, z1);
    mul_mod(y, y, z1);
    copy_eight(x1, x);
    copy_eight(y1, y);
}
