#include "kernel/bip39.cl"
#include "kernel/bloom_filter.cl"
#include "kernel/common.cl"
#include "kernel/ec.cl"
#include "kernel/sha512.cl"
#include "kernel/hmac_sha512.cl"
#include "kernel/pbkdf2_hmac_sha512.cl"
#include "kernel/ripemd_beech.cl"
#include "kernel/sha256.cl"
#include "kernel/derive.cl"

#define PBKDF2_MSG 7885351518267664739

#ifdef ELECTRUM_SEED
#undef PBKDF2_MSG
#define PBKDF2_MSG 7308327773145298285ULL
#endif

typedef struct {
  uchar mnemo[128];
  uchar address[92];
} test_t;

__kernel void verify(__global test_t *seedStringTest, const ulong offset_part,
                     const ulong high_part, __global ulong *addrs,
                     const uint addrs_size, __constant const uint *NAFS,
                     __constant const uint *BIP39_SEEDS_COMBINATION,
                     __constant const uint *BIP39_SEEDS_COMBINATION_LEN,
                     __global ulong *PASSWORDS_FROM_WORDLIST,
                     const uint WORDLIST_SIZE, __global hit_t *out_hits,
                     OUTCNT_ARG out_count, __global const uint *bf_bits,
                     const uint bf_mask, const uint bf_words_mask) {
  ulong pbkdLong[16] = {0};
  ulong mnemonicLong[16] = {0};

  ulong x = offset_part + (ulong)get_global_id(0), off = 0;
  uint seedNum[12] = {0};
  uchar mnemonicString[128] = {0};

#if !defined(COMBINATIONAL)
  prepareSeedNumber(seedNum, high_part, x);
  for (int i = 0, seedStrNum=0, bipLen=0; i < 12; i++) {
    seedStrNum = seedNum[i];
    bipLen = (uint)wordsLen[seedStrNum];
    for (uint j = 0; j < bipLen; ++j) {
      mnemonicString[off++] = (uchar)wordsString[seedStrNum][j];
    }
    mnemonicString[off++] = (uchar)' ';
  }
  mnemonicString[off - 1] = '\0';
#endif

#if defined(COMBINATIONAL)
  ulong temp = x;
  uint dpos[12]={0};
#pragma unroll
  for (int t = 0; t < 12; ++t) {
    int k = 11 - t;
    uint Li = BIP39_SEEDS_COMBINATION_LEN[k];
    uint d = (uint)(temp % (ulong)Li);
    temp /= (ulong)Li;
    dpos[k] = d;
  }
  off = 0;
#pragma unroll
  for (int i = 0; i < 12; ++i) {
    uint Li = BIP39_SEEDS_COMBINATION_LEN[i];
    uint d = dpos[i];
    uint flat_widx = (uint)i * 2048u + d;
    uint wi1b = BIP39_SEEDS_COMBINATION[flat_widx];
    uint word_index = wi1b - 1u;
    seedNum[i] = word_index;
    uint bipLen = (uint)wordsLen[word_index];
    for (uint j = 0; j < bipLen; ++j) {
      mnemonicString[off++] = (uchar)wordsString[word_index][j];
    }
    mnemonicString[off++] = (uchar)' ';
  }
  mnemonicString[off - 1] = (uchar)'\0';
#endif

#if defined(COMBINATIONAL) && !defined(ELECTRUM_SEED)
  if (!bip39_checksum_valid_12(seedNum)) {
    return;
  }
#endif

  ucharLong(mnemonicString, off - 1, mnemonicLong, 0);

#if defined(ELECTRUM_SEED)
  ulong G[8] = {0};
  hmac_sha512_seed_version(mnemonicLong, G, off);
  if ((((G[0] >> 60) & 0xFUL) != 1UL) ||
      (((G[0] >> 52) & 0xFFFUL) != 0x100UL)) {
    return;
  }
#endif

  ulong hmacSeedOutput[8] = {0};
  __private ulong inner_data[32] = {mnemonicLong[0] ^ IPAD,
                                    mnemonicLong[1] ^ IPAD,
                                    mnemonicLong[2] ^ IPAD,
                                    mnemonicLong[3] ^ IPAD,
                                    mnemonicLong[4] ^ IPAD,
                                    mnemonicLong[5] ^ IPAD,
                                    mnemonicLong[6] ^ IPAD,
                                    mnemonicLong[7] ^ IPAD,
                                    mnemonicLong[8] ^ IPAD,
                                    mnemonicLong[9] ^ IPAD,
                                    mnemonicLong[10] ^ IPAD,
                                    mnemonicLong[11] ^ IPAD,
                                    mnemonicLong[12] ^ IPAD,
                                    mnemonicLong[13] ^ IPAD,
                                    mnemonicLong[14] ^ IPAD,
                                    mnemonicLong[15] ^ IPAD,
                                    PBKDF2_MSG,
                                    6442450944UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    1120UL};
#define BIG_ENDIAN_PASSWORD
  __private ulong outer_data[32] = {mnemonicLong[0] ^ OPAD,
                                    mnemonicLong[1] ^ OPAD,
                                    mnemonicLong[2] ^ OPAD,
                                    mnemonicLong[3] ^ OPAD,
                                    mnemonicLong[4] ^ OPAD,
                                    mnemonicLong[5] ^ OPAD,
                                    mnemonicLong[6] ^ OPAD,
                                    mnemonicLong[7] ^ OPAD,
                                    mnemonicLong[8] ^ OPAD,
                                    mnemonicLong[9] ^ OPAD,
                                    mnemonicLong[10] ^ OPAD,
                                    mnemonicLong[11] ^ OPAD,
                                    mnemonicLong[12] ^ OPAD,
                                    mnemonicLong[13] ^ OPAD,
                                    mnemonicLong[14] ^ OPAD,
                                    mnemonicLong[15] ^ OPAD,
                                    6655295901103053916UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0x8000000000000000UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    0UL,
                                    1536UL};

  pbkdf2_hmac_sha512_long(inner_data, outer_data, pbkdLong);
  hmac_sha512_bitcoin_seed(pbkdLong, hmacSeedOutput);

  uint X[8] = {0}, Y[8] = {0};
  ulong k[4] = {0}, c[4] = {0};

#ifdef ELECTRUM_SEED
  if (!derive_m_purposeh_0_i_pub(hmacSeedOutput, 0u, 0u, k, c, X, Y, NAFS)) {
    return;
  }
#else
  if (!derive_m_84h_0h_0h_change_i_pub(hmacSeedOutput, 0ul, 0ul, k, c, X, Y,
                                       NAFS)) {
    return;
  }
#endif
  const uint lsz = get_local_size(0);
  ulong tag64 = b32sw_tag64_from_xy_le(X, Y);
  uint global_base = get_global_id(0) * 5;

  if ((!get_global_id(0))) {
    b32sw_p2wpkh_addr_bc_from_xy_le(X, Y, seedStringTest->address, 92);
    for (int i = 0; i < off; ++i) {
      seedStringTest[0].mnemo[i] = mnemonicString[i];
    }
  }
  checkAndHitAddress(bf_bits, bf_mask, bf_words_mask, addrs, addrs_size,
                     out_hits, PASSWORDS_FROM_WORDLIST, WORDLIST_SIZE, seedNum,
                     tag64, global_base, out_count);
}
