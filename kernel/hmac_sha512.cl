
/*
 *   HMAC-SHA-512
 *    A streamlined implementation of the HMAC-SHA-512 algorithm using ulongs.
 *    Minimizes memory usage and reduces instruction count to boost performance.
 *    Works only with 6x4 bytes keys
 *       github.com/ipsbruno
 */

#define IPAD 0x3636363636363636UL
#define OPAD 0x5c5c5c5c5c5c5c5cUL

#define BITCOIN_SEED 0x426974636f696e20UL, 0x7365656400000000UL, 0, 0
#define SEED_VERSION  0x5365656420766572ULL, 0x73696f6e00000000ULL, 0ULL, 0ULL

#define REPEAT_2(x) x, x
#define REPEAT_4(x) REPEAT_2(x), REPEAT_2(x)
#define REPEAT_5(x) REPEAT_4(x), x
#define REPEAT_6(x) REPEAT_4(x), REPEAT_2(x)
#define REPEAT_7(x) REPEAT_4(x), REPEAT_2(x), x
#define REPEAT_8(x) REPEAT_4(x), REPEAT_4(x)
#define REPEAT_16(x) REPEAT_8(x), REPEAT_8(x)
#define SHOW_ARR(x) x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]

void hmac_sha512_32bytes(ulong *key, ulong *message, ulong *H) {
  ulong inner[32] = {key[0] ^ IPAD,     key[1] ^ IPAD,
                     key[2] ^ IPAD,     key[3] ^ IPAD,
                     REPEAT_6(IPAD),    REPEAT_6(IPAD),
                     SHOW_ARR(message), 0x8000000000000000UL,
                     REPEAT_6(0),       1536};
  ulong outer[32] = {key[0] ^ OPAD,        key[1] ^ OPAD,   key[2] ^ OPAD,
                     key[3] ^ OPAD,        REPEAT_16(OPAD), REPEAT_4(OPAD),
                     0x8000000000000000UL, REPEAT_6(0),     1536};
  sha512_hash_two_blocks_message(inner, H);
  COPY_EIGHT(outer + 16, H);
  sha512_hash_two_blocks_message(outer, H);
}

void hmac_sha512_bitcoin_seed(ulong *message, ulong *H) {
  ulong key[4] = {BITCOIN_SEED};
  hmac_sha512_32bytes(key, message, H);
}


static inline int hmac_sha512_key32_msg_upto111_fast(
    ulong key[4],
    ulong *  msg,
    ushort mlen,
    ulong * H)
{
    if (mlen > 111u) return 0;

    const uint w  = mlen >> 3;        
    const uint r  = mlen & 7u;        
    const uint sh = (7u - r) << 3;    

    ulong inner[32] = {
        key[0]^IPAD, key[1]^IPAD, key[2]^IPAD, key[3]^IPAD,
        IPAD,IPAD,IPAD,IPAD, IPAD,IPAD,IPAD,IPAD, IPAD,IPAD,IPAD,IPAD,
        0UL,0UL,0UL,0UL, 0UL,0UL,0UL,0UL, 0UL,0UL,0UL,0UL, 0UL,0UL,0UL,0UL
    };

    switch (w) {
        case 13: inner[28] = msg[12];
        case 12: inner[27] = msg[11];
        case 11: inner[26] = msg[10];
        case 10: inner[25] = msg[9];
        case  9: inner[24] = msg[8];
        case  8: inner[23] = msg[7];
        case  7: inner[22] = msg[6];
        case  6: inner[21] = msg[5];
        case  5: inner[20] = msg[4];
        case  4: inner[19] = msg[3];
        case  3: inner[18] = msg[2];
        case  2: inner[17] = msg[1];
        case  1: inner[16] = msg[0];
        default: break;
    }

    inner[16 + w] = msg[w] | (0x80UL << sh);
    inner[31] = (ulong)((128u + mlen) << 3);
    sha512_hash_two_blocks_message(inner, H);

    ulong outer[32] = {
        key[0]^OPAD, key[1]^OPAD, key[2]^OPAD, key[3]^OPAD,
        OPAD,OPAD,OPAD,OPAD, OPAD,OPAD,OPAD,OPAD, OPAD,OPAD,OPAD,OPAD,
        0UL,0UL,0UL,0UL, 0UL,0UL,0UL,0UL,
        0x8000000000000000UL, 0UL,0UL,0UL, 0UL,0UL,0UL, 1536UL
    };

    outer[16]=H[0]; outer[17]=H[1]; outer[18]=H[2]; outer[19]=H[3];
    outer[20]=H[4]; outer[21]=H[5]; outer[22]=H[6]; outer[23]=H[7];
    sha512_hash_two_blocks_message(outer, H);
    return 1;
}


void hmac_sha512_seed_version(ulong *message, ulong *H, ushort key_len) {
  ulong key[4] = {SEED_VERSION};
  hmac_sha512_key32_msg_upto111_fast(key, message, key_len, H);
}


