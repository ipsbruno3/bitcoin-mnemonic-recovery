import warnings
import numpy as np
import pyopencl as cl


warnings.filterwarnings(
    "ignore",
    category=RuntimeWarning,
    message=r".*overflow encountered in scalar.*"
)



def _mix64(x: np.uint64) -> np.uint64:
    x ^= x >> np.uint64(33)
    x *= np.uint64(0xff51afd7ed558ccd)
    x ^= x >> np.uint64(33)
    x *= np.uint64(0xc4ceb9fe1a85ec53)
    x ^= x >> np.uint64(33)
    return x

def build_bloom_u32(tags_u64: np.ndarray, nbits_pow2: int = 1<<27, k: int = 4):
    assert (nbits_pow2 & (nbits_pow2 - 1)) == 0
    nwords = nbits_pow2 // 32
    bf = np.zeros(nwords, dtype=np.uint32)

    mask = np.uint64(nbits_pow2 - 1)

    for t in tags_u64.astype(np.uint64, copy=False):
        h1 = _mix64(t ^ np.uint64(0x9e3779b97f4a7c15))
        h2 = _mix64(t ^ np.uint64(0xbf58476d1ce4e5b9)) | np.uint64(1)
        for i in range(k):
            idx = np.uint64(h1 + np.uint64(i) * h2) & mask
            w = np.uint32(idx >> np.uint64(5))
            b = np.uint32(idx & np.uint64(31))
            bf[w] |= (np.uint32(1) << b)
    return bf, np.uint32(nbits_pow2 - 1), np.uint32(nwords - 1)


def upload_bloom(ctx, bf_u32):
    bf_u32 = np.ascontiguousarray(bf_u32, dtype=np.uint32)
    return cl.Buffer(ctx, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=bf_u32)