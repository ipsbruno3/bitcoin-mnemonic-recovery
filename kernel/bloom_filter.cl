
#if __OPENCL_C_VERSION__ >= 200
#define OUTCNT_ARG __global atomic_uint *
#define OUTCNT_FETCH()                                                         \
  atomic_fetch_add_explicit(out_count, 1u, memory_order_relaxed,               \
                            memory_scope_device)
#else
#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable
#pragma OPENCL EXTENSION cl_khr_local_int32_base_atomics : enable
#define OUTCNT_ARG __global volatile uint *
#define OUTCNT_FETCH() atomic_inc(out_count)
#endif

typedef struct {
  ushort widx[12];
  ulong tag64;
  ulong address;
} hit_t;

static inline ulong mix64(ulong x) {
  x ^= x >> 33;
  x *= (ulong)0xff51afd7ed558ccdUL;
  x ^= x >> 33;
  x *= (ulong)0xc4ceb9fe1a85ec53UL;
  x ^= x >> 33;
  return x;
}

static inline int bloom_test_tag64(
    __global const uint *bf,   
    const uint bf_mask,        
    const uint bf_words_mask,  
    const ulong tag64
){
  ulong h1 = mix64(tag64 ^ (ulong)0x9e3779b97f4a7c15UL);
  ulong h2 = mix64(tag64 ^ (ulong)0xbf58476d1ce4e5b9UL) | 1UL; 

  for (uint i = 0; i < 4; i++) {
    uint idx = (uint)((h1 + (ulong)i * h2) & (ulong)bf_mask);
    uint w   = (idx >> 5) & bf_words_mask;
    uint b   = idx & 31U;
    uint m   = 1U << b;
    if ((bf[w] & m) == 0U) return 0;
  }
  return 1;
}

static inline int binary_search_u64(__global const ulong *arr, uint n, ulong key){
  uint lo = 0, hi = n;
  while (lo < hi){
    uint mid = (lo + hi) >> 1;
    ulong v = arr[mid];
    if (v < key) lo = mid + 1;
    else hi = mid;
  }
  return (lo < n && arr[lo] == key);
}

static inline int checkAndHitAddress(
    __global const uint  *bf_bits,    
    const uint bf_mask,               
    const uint bf_words_mask,          
    __global const ulong *addrs,
    const uint addrs_size,
    __global hit_t *out_hits,
    __global ulong * PASSWORDS_FROM_WORDLIST,
    const uint WORDLIST_SIZE,   
    uint seedNum[12],
    ulong tag64,
    ulong global_base,
    OUTCNT_ARG out_count
    ) {
    
    if (bloom_test_tag64(bf_bits, bf_mask, bf_words_mask, tag64)) {
    	if (binary_search_u64(addrs, addrs_size, tag64)) {
			const uint slot = (uint)OUTCNT_FETCH();
			for (int j = 0; j < 12; ++j) {
				out_hits[slot].widx[j] = seedNum[j];				
			}
      out_hits[slot].tag64 = tag64;
		}
	}
}
