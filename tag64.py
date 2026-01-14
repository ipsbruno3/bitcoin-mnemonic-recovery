from __future__ import annotations
import gzip
import numpy as np
from bech32 import bech32_decode, convertbits
import pyopencl as cl


def decode_addr(addr: str):
    hrp, data = bech32_decode(addr)
    if hrp is None or not data:
        raise ValueError("Bech32 inválido/sem payload")

    ver = data[0]
    prog = bytes(convertbits(data[1:], 5, 8, False) or [])
    if not (0 <= ver <= 16):
        raise ValueError("Versão witness inválida")
    return hrp, ver, prog


def _open_text_auto(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return open(path, "rt", encoding="utf-8", errors="ignore")


def build_tags_u64_from_file(
    base_path: str,
    hrps=("bc", "tb"),
    ver_filter=None,      
    unique=False,         
):
    hrps = tuple(h.lower() for h in hrps)
    prefixes = tuple(h + "1" for h in hrps)

    tags = []
    total = ok = 0
    with _open_text_auto(base_path) as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            total += 1
            addr = s.split(None, 1)[0]
            if not addr.startswith(prefixes):
                continue
            try:
                hrp, ver, prog = decode_addr(addr)
            except Exception:
                continue
            if hrp not in hrps:
                continue
            if ver_filter is not None and ver != ver_filter:
                continue
            if len(prog) < 8: 
                continue
            tags.append(int.from_bytes(prog[:8], "little"))
            ok += 1
    tags_u64 = np.asarray(tags, dtype=np.uint64)
    if unique and tags_u64.size:
        tags_u64 = np.unique(tags_u64)
    stats = {"linhas_lidas": total, "tags_geradas": ok, "unique": bool(unique)}
    return tags_u64, stats


def load_target_addresses(ctx):
    tags_u64, _ = build_tags_u64_from_file(
        "addresses.txt", hrps=("bc",), ver_filter=0, unique=True
    )
    tags_u64 = np.ascontiguousarray(tags_u64, dtype=np.uint64)
    tags_u64.sort() 
    buf = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=tags_u64)
    return buf, np.uint32(tags_u64.size), tags_u64  