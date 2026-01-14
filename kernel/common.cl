


#define COPY_EIGHT(a, b)                                                       \
  (a)[0] = (b)[0], (a)[1] = (b)[1], (a)[2] = (b)[2], (a)[3] = (b)[3],          \
  (a)[4] = (b)[4], (a)[5] = (b)[5], (a)[6] = (b)[6], (a)[7] = (b)[7];

#define COPY_EIGHT_XOR(a, b)                                                   \
  (a)[0] ^= (b)[0];                                                            \
  (a)[1] ^= (b)[1];                                                            \
  (a)[2] ^= (b)[2];                                                            \
  (a)[3] ^= (b)[3];                                                            \
  (a)[4] ^= (b)[4];                                                            \
  (a)[5] ^= (b)[5];                                                            \
  (a)[6] ^= (b)[6];                                                            \
  (a)[7] ^= (b)[7];


#define DEBUG_ARRAY(name, array, len)                                          \
  do {                                                                         \
    for (uint i = 0; i < (len); i++) {                                         \
      printf("%s[%d] = %d\n",name,i, (array)[i]);                                       \
    }                                                                          \
                                                                  \
  } while (0)

uint strlen(uchar *s) {
  uint l;
  for (l = 0; s[l] != '\0'; l++) {
    continue;
  }
  return l;
}


#define ucharLong(input, input_len, output, offset)                            \
  {                                                                            \
    const uchar num_ulongs = (input_len + 7) / 8;                              \
    for (uchar i = offset; i < num_ulongs; i++) {                              \
      const uchar baseIndex = i * 8;                                           \
      output[i] = ((ulong)input[baseIndex] << 56UL) |                          \
                  ((ulong)input[baseIndex + 1] << 48UL) |                      \
                  ((ulong)input[baseIndex + 2] << 40UL) |                      \
                  ((ulong)input[baseIndex + 3] << 32UL) |                      \
                  ((ulong)input[baseIndex + 4] << 24UL) |                      \
                  ((ulong)input[baseIndex + 5] << 16UL) |                      \
                  ((ulong)input[baseIndex + 6] << 8UL) |                       \
                  ((ulong)input[baseIndex + 7]);                               \
    }                                                                          \
    for (uchar i = num_ulongs; i < 16; i++) {                                  \
      output[i] = 0;                                                           \
    }                                                                          \
  }

   #ifndef ELECTRUM_SEED
#define prepareSeedNumber(seedNum, memHigh, memLow)                            \
  seedNum[0] = (memHigh & (2047UL << 53UL)) >> 53UL;                           \
  seedNum[1] = (memHigh & (2047UL << 42UL)) >> 42UL;                           \
  seedNum[2] = (memHigh & (2047UL << 31UL)) >> 31UL;                           \
  seedNum[3] = (memHigh & (2047UL << 20UL)) >> 20UL;                           \
  seedNum[4] = (memHigh & (2047UL << 9UL)) >> 9UL;                             \
  seedNum[5] = (memHigh << 55UL) >> 53UL | ((memLow & (3UL << 62UL)) >> 62UL); \
  seedNum[6] = (memLow & (2047UL << 51UL)) >> 51UL;                            \
  seedNum[7] = (memLow & (2047UL << 40UL)) >> 40UL;                            \
  seedNum[8] = (memLow & (2047UL << 29UL)) >> 29UL;                            \
  seedNum[9] = (memLow & (2047UL << 18UL)) >> 18UL;                            \
  seedNum[10] = (memLow & (2047UL << 7UL)) >> 7UL;                             \
  seedNum[11] =                                                                \
      (memLow << 57UL) >> 53UL | sha256_first_byte(memHigh, memLow) >> 4UL;
  
#else
#define prepareSeedNumber(seedNum, memHigh, memLow)                            \
  seedNum[0] = (memHigh & (2047UL << 53UL)) >> 53UL;                           \
  seedNum[1] = (memHigh & (2047UL << 42UL)) >> 42UL;                           \
  seedNum[2] = (memHigh & (2047UL << 31UL)) >> 31UL;                           \
  seedNum[3] = (memHigh & (2047UL << 20UL)) >> 20UL;                           \
  seedNum[4] = (memHigh & (2047UL << 9UL)) >> 9UL;                             \
  seedNum[5] = (memHigh << 55UL) >> 53UL | ((memLow & (3UL << 62UL)) >> 62UL); \
  seedNum[6] = (memLow & (2047UL << 51UL)) >> 51UL;                            \
  ulong combo = (ulong)memLow;\
  seedNum[11] = combo % 2048ul; combo /= 2048ul;\
  seedNum[10] = combo % 2048ul; combo /= 2048ul;\
  seedNum[9] = combo % 2048ul; combo /= 2048ul;\
  seedNum[8] = combo % 2048ul; combo /= 2048ul;\
  seedNum[7] = combo % 2048ul;
#endif

#define STORE8(p,v) vstore8((v), 0, (__private ulong*)(p))
#define LOAD8(p)    vload8(0, (__private const ulong*)(p))

