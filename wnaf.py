
import numpy as np

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def modinv(a):
    return pow(a, P - 2, P)

def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if x1 == x2 and y1 == y2: return point_double(p1)
    dx = (x2 - x1) % P
    dy = (y2 - y1) % P
    lam = (dy * modinv(dx)) % P
    x3 = (lam * lam % P - x1 - x2) % P
    y3 = (lam * (x1 - x3) % P - y1) % P
    return (x3, y3)

def point_double(p):
    if p is None: return None
    x, y = p
    if y == 0: return None
    temp = (2 * y) % P
    lam = (3 * x * x % P) * modinv(temp) % P
    x3 = (lam * lam % P - 2 * x) % P
    y3 = (lam * (x - x3) % P - y) % P
    return (x3, y3)

def to_uint32_le(n):
    words = np.empty(8, dtype=np.uint32)
    for i in range(8):
        words[i] = n & 0xFFFFFFFF
        n >>= 32
    return words

def gen_precomputed_table(w: int) -> np.ndarray:
    num_points = 1 << (w - 1)  
    total_words = num_points * 24
    G = (GX, GY)
    twoG = point_double(G)
    table = np.zeros(total_words, dtype=np.uint32)
    cur = G
    for i in range(num_points):
        x, y = cur
        neg_y = (P - y) % P 
        base = i * 24
        table[base:base+8] = to_uint32_le(x)
        table[base+8:base+16] = to_uint32_le(y)
        table[base+16:base+24] = to_uint32_le(neg_y)
        cur = point_add(cur, twoG)
    return table
