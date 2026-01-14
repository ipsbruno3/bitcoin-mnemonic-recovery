from mnemonic import Mnemonic
import numpy as np
import hashlib
import re
from itertools import cycle, islice
import mnem

BIP39_STRIDE = 12 
WORDLIST = Mnemonic("english").wordlist
BIP39 = np.zeros(len(WORDLIST) * BIP39_STRIDE, dtype=np.uint8)
INDEX_OF = {w: i for i, w in enumerate(WORDLIST)}




def words_to_indices(words, *, strict=True, dtype=np.uint16):
    idx = [] 
    missing = []
    for w in words:
        try:
            idx.append(INDEX_OF[w])
        except KeyError:
            if strict:
                missing.append(w)
    return np.array(idx, dtype=dtype)
 


def words_from_indices(indices12) -> str:
    return " ".join(WORDLIST[int(x)] for x in indices12)



def count_placeholders(template: str, placeholder: str = "?") -> tuple[int, bool]:
    tokens = template.strip().split()
    n = sum(1 for t in tokens if t == placeholder)
    last_is_placeholder = bool(tokens) and tokens[-1] == placeholder
    return n, last_is_placeholder



def search_space_size(n_missing: int, last_missing: bool, base_default: int, base_last: int) -> int:
    if n_missing <= 0:
        return 1
    if last_missing and n_missing >= 1:
        return (base_default ** (n_missing - 1)) * base_last
    return base_default ** n_missing


def mnemonic_to_uint64_pair(indices):
    bits = ''.join(f"{index:011b}" for index in indices)
    if len(bits) != 132:
        raise ValueError(f"Esperado 132 bits (12 palavras), mas tem {len(bits)}")
    entropy_bits = bits[:-4]
    if len(entropy_bits) != 128:
        raise ValueError(f"Após remover checksum, esperado 128 bits, mas tem {len(entropy_bits)}")
    high = int(entropy_bits[:64], 2)
    low = int(entropy_bits[64:], 2)
    
    return high, low

def _mnemonic_to_words(mn):
    if isinstance(mn, (list, tuple)):
        return list(mn)
    return str(mn).strip().split()

MISSING_POS = []
def set_redaction(missing_pos=None):
    global MISSING_POS
    MISSING_POS = list(missing_pos or [])

def changeSeed(widx_u16):
    w = np.array(widx_u16, dtype=np.uint16, copy=True)
    full_words = _mnemonic_to_words(mnem.words_from_indices(w))
    full_str = " ".join(full_words)

    found_parts = [f"{i+1}:{full_words[i]}" for i in MISSING_POS if i < len(full_words)]
    display_str = " ".join(found_parts) if found_parts else "<no-missing-words?>"
    w.fill(0)
    return full_str, display_str
    


def uint64_pair_to_mnemonic(high, low):
    entropy = (high << 64) | low
    entropy_bytes = entropy.to_bytes(16, 'big')
    hash_bytes = hashlib.sha256(entropy_bytes).digest()
    checksum = hash_bytes[0] >> 4
    full_value = (entropy << 4) | checksum
    indices = [(full_value >> (11 * i)) & 0x7FF for i in range(11, -1, -1)]
    return indices



def uint64_pair_to_phrase(high, low, lang="english"):
    m = Mnemonic(lang)
    indices = uint64_pair_to_mnemonic(high, low)
    words = [m.wordlist[i] for i in indices]
    return " ".join(words)




def replace_placeholder(text):
    result = ' '.join('?' if w.startswith('?') and len(w) > 1 and w[1:].isalpha() else w for w in text.split())
    return (result.replace('?','abandon'))



def mnemonic_to_uint64_pair(indices):
    bits = ''.join(f"{index:011b}" for index in indices)
    if len(bits) != 132:
        raise ValueError(f"Esperado 132 bits (12 palavras), mas tem {len(bits)}")
    entropy_bits = bits[:-4]
    if len(entropy_bits) != 128:
        raise ValueError(f"Após remover checksum, esperado 128 bits, mas tem {len(entropy_bits)}")
    high = int(entropy_bits[:64], 2)
    low = int(entropy_bits[64:], 2)
    
    return high, low

def is_checksum_verification(s: str) -> bool:
    toks = s.strip().split()
    if not toks:
        return False
    if toks[0] == "?":
        return False
    if "?" not in toks:
        return True
    first_q = toks.index("?")
    return all(t == "?" for t in toks[first_q:])


def words_to_indices(words, *, strict=True, dtype=np.uint16):
    idx = [] 
    missing = []
    for w in words:
        try:
            idx.append(INDEX_OF[w])
        except KeyError:
            if strict:
                missing.append(w)
    return np.array(idx, dtype=dtype)
 

def words_to_array_int_comma(SEED):
    fixed_words = SEED.strip().lower().split()
    if len(fixed_words) != 12:
        raise ValueError("Para BRUTE_PASSWORD_NOT_SEED, a SEED deve ter exatamente 12 palavras.")
    for w in fixed_words:
        if w not in INDEX_OF:
            raise ValueError(f"Palavra desconhecida na mnemonic fixa: '{w}'")
    return ",".join(map(str, [INDEX_OF[w] for w in fixed_words])) 

def count_placeholders(template: str, placeholder: str = "?") -> tuple[int, bool]:
    tokens = template.strip().split()
    n = sum(1 for t in tokens if t == placeholder)
    last_is_placeholder = bool(tokens) and tokens[-1] == placeholder
    return n, last_is_placeholder

def search_space_size(n_missing: int, last_missing: bool, base_default: int, base_last: int) -> int:
    if n_missing <= 0:
        return 1
    if last_missing and n_missing >= 1:
        return (base_default ** (n_missing - 1)) * base_last
    return base_default ** n_missing

def uint64_pair_to_mnemonic(high, low):
    entropy = (high << 64) | low
    entropy_bytes = entropy.to_bytes(16, 'big')
    hash_bytes = hashlib.sha256(entropy_bytes).digest()
    checksum = hash_bytes[0] >> 4
    full_value = (entropy << 4) | checksum
    indices = [(full_value >> (11 * i)) & 0x7FF for i in range(11, -1, -1)]
    return indices

def uint64_pair_to_phrase(high, low, lang="english"):
    m = Mnemonic(lang)
    indices = uint64_pair_to_mnemonic(high, low)
    words = [m.wordlist[i] for i in indices]
    return " ".join(words)






def get_bip39_combinations(words, wordlist):
    if len(words) != 12:
        raise ValueError("Erro: a seed deve ter exatamente 12 palavras")
    ph_re = re.compile(r"^\?[A-Za-z]*$")  
    idx_of = {w: i for i, w in enumerate(wordlist)}  
    flat_combinations = np.empty(12 * 2048, dtype=np.uint16)
    lens = np.zeros(12, dtype=np.uint32)
    combinational = False
    for pos in range(12):
        w = words[pos]
        w_lower = w.lower()
        base = pos * 2048
        if ph_re.match(w):
            prefix = w_lower[1:]  
            if prefix == "":
                candidates = list(range(2048))
            else:
                candidates = [i for i, wd in enumerate(wordlist) if wd.startswith(prefix)]
                if not candidates:
                    candidates = list(range(2048))
                else:
                    combinational = True
        else:
            if w_lower not in idx_of:
                raise ValueError(f"Palavra inválida na posição {pos+1}: '{w}'")
            candidates = [idx_of[w_lower]]
        real_count = len(candidates)     
        lens[pos] = real_count
        if real_count == 2048:
            padded = candidates
        else:
            padded = list(islice(cycle(candidates), 2048))
        flat_combinations[base:base + 2048] = (np.asarray(padded, dtype=np.uint16) + 1)
    return flat_combinations.tolist(), lens.tolist(), combinational
