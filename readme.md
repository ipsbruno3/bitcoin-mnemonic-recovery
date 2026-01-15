

<img width="817" height="305" alt="image" src="https://github.com/user-attachments/assets/a46029e5-18d9-4d67-af77-a154078fe7d6" />

- 🧬 Bruno da Silva — Security Researcher | Blockchain & Cryptography
- 📧 bsbruno@proton.me
- 📱 +55 11 99740‑2197

- GitHub: ipsbruno | ipsbrunoreserva | ipsbruno3
- Pastebin: ipsBruno | Drakins

## This repo contains the world's fastest BIP39 seed recovery.

11 million per second, if you consider checksum 176 million per second;
<img width="629" height="732" alt="image" src="https://github.com/user-attachments/assets/7d121b71-896c-4245-916d-3305417f851d" />


# 🥇 Bitcoin Recovery Services

We provide assisted wallet seed and password recovery for users who have lost access to their funds, for a **fixed fee of $1,000**.

Our key differentiator is **non-custodial support**: at no point do **we ask for your seed phrase or take control of your wallet**. Instead, we guide you step-by-step on how to install and use the tools, and how to set up your own recovery rig in the safety of your own home, without trusting third parties.


We develop specialized software and hardware for mass seed searching.


<img width="2293" height="1174" alt="image" src="https://github.com/user-attachments/assets/54d93419-262d-4144-bf64-3adb7d7f03e8" />
<img width="2377" height="926" alt="image" src="https://github.com/user-attachments/assets/54c76407-56fc-42f8-a24f-d627f78fa438" />

We guarantee the best performance in highly parallelizable and scalable software and hardware for your and your company's self-recovery. Request a quote by emailing us below.

_In very specific cases, its possible we can recover up to 6 words missing the 12 seeds, if cost are not restrictive_

**Contact:** bsbruno@proton.me

On this GitHub, you’ll find some of the most optimized codebases for seed searches, including highly parallelizable software implementations and open-source hardware/ASIC designs used across the recovery industry.


<img width="2314" height="1011" alt="image" src="https://github.com/user-attachments/assets/622ecd8b-e7dc-4345-b422-7de5feab231f" />


Thank you at all

---
### ⚠️ This project is intended **exclusively** for **lawful** recovery of wallets owned by the user. Unauthorized use against third‑party wallets is strictly prohibited.
---


# ⚡ Bitcoin Seed Recovery (GPU)

## 📌 Quick overview
This project performs **GPU‑accelerated mnemonic recovery** (BIP‑39 and Electrum) via OpenCL. The focus is recovering phrases with **missing words** and comparing the first derived address against a target list (bc1 Bech32 addresses).

**Real‑world performance (current optimizations):**
- 🚀 **RTX 5090**: ~**1,000,000 KHash/s**  in optimized pipelines.
- 💻 **RTX 4070 Laptop**: ~**150.000 KHash/s**.

> These figures depend on driver, clocks, power limits, and mode (Electrum vs BIP‑39). See benchmarks below for more context.

---

## 🧠 Processing flow (high level)
1. **Input (Python host)**
   - Reads a target address file (`addresses.txt`) (one address per line)
2. **OpenCL kernel**
   - Generates 12‑word candidates from `(memHigh, memLow)`.
   - Derives the first address (BIP‑84 or Electrum, depending on mode).
   - Compares against targets and writes hits to a buffer.
3. **Output (Python host)**
   - Reconstructs the found mnemonic and saves to `encontrados.txt`.
   - Updates UI and state (`state.json`).


---


## ⭐ Highlights

- **Highly competitive PBKDF2 engine** capable of **tens of millions of executions per second** on modern GPUs. Purpose-built for **Bitcoin BIP-39 mnemonic recovery / brute-force workflows**, targeting higher throughput than established tools such as **John the Ripper** and **Hashcat** in comparable scenarios.

- **Performance-focused cryptographic pipeline optimizations**
  - Massive pipeline depth in the critical path
  - Aggressive loop unrolling across cryptographic primitives
  - Custom algorithmic improvements (e.g., optimized **MAJ reuse/recomputation in SHA-512**)
  - Fine-grained register rotation/renaming to reduce register pressure and instruction count, minimizing the need to manipulate the full SHA state **(a,b,c,d,e,f,g,h)** and focusing updates on the most relevant registers per round

- **Fast address verification: Bloom prefilter + structured lookup**
  - Runs a Bloom filter inside the OpenCL hot path, enabling **millions of addresses to be filtered in parallel** without degrading kernel throughput
  - Uses binary-tree lookup after the “inner bloom” pass, reducing final verification cost from **O(n)** to **O(log n)**

- **Remote state persistence (3 layers)**
  - **Sequential search:** remote checkpointing via `reports.py` for reliable resume after interruption (used in large stride deployments, e.g., trillion-step strides per rig segmented into thousands of parts for multi-quadrillion search spaces)
  - **RANDOM search:** compact Bloom dedup layer (≈ **1–10 billion** entries) to reduce long-term repetition and random-walk noise
  - **Partial seed constraints:** supports prefix hints like `?b` (e.g., `"word word word ?b word ..."`) to reduce the search space, with an expected throughput penalty in highly non-sequential layouts due to reduced checksum pruning

- **Optimized ECC: wNAF + Jacobian coordinates**
  - Python precomputes base tables/points on the host and uploads ready-to-use data to OpenCL kernels
  - Recommended wNAF windows: **2 to 6 bits**, depending on GPU architecture

- **Telegram notifications**
  - Optional notifications for benchmarks, progress, and hit/results for real-time monitoring
<img width="1563" height="762" alt="image" src="https://github.com/user-attachments/assets/6909f83a-f3ac-4771-974f-245e088aa03c" />


- **Bech32 tag64 acceleration**
  - Custom **tag64** representation converts Bech32 addresses into compact **64-bit tags**, enabling faster membership checks by avoiding full Bech32 reconstruction in every trial

- **BIP-39 ↔ Electrum mode switch**
  - Supports standard **BIP-39/BIP-84** as well as **Electrum** mode
  - Electrum mode performs a **checksum validation step before PBKDF2**, reducing the search space by **4096×**

- **OpenCL throughput + scalability**
  - OpenCL-first architecture focused on maximum throughput and efficient scaling on high-end rigs (e.g., multi-GPU deployments)
  - Actively developed; contributions are welcome

- **Low-level optimization strategy (pointers, vectors, macros)**
  - Extensive `#define` usage to push configuration decisions to compile time (fewer runtime branches / fewer instructions in the hot path)
  - Strategic use of vector types like `ulong4` to leverage SIMD and reduce assignment overhead
  - Heavy pointer/reference passing to minimize copies and memory traffic
  - Preference for **ulong-based BIG-INT style representations** over byte-by-byte `uchar` operations in critical paths

- **Native multi-GPU integration**
  - Automatically detects and enumerates all GPUs
  - Assigns an independent stride per GPU and runs separate highly-parallel kernels per device (no duplicated work)

- **Rich UI Console**
- <img width="502" height="665" alt="image" src="https://github.com/user-attachments/assets/f66b4292-1752-49fc-881e-30d3a55868cc" />



---

## ✅ Requirements
- Linux + recent NVIDIA driver (OpenCL runtime is included with the driver)
- Python 3.10+

---

## ⚙️ Installation (Linux)

```bash
sudo apt update
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```



## 🔧 Configuration (.env)

| Variable | Description | Default |
|---------|-------------|---------|
| `SEED` | Partial mnemonic. Use `?` for missing words. | **required** |
| `GPU_THREADS` | Total threads per kernel batch. | `32000` |
| `SAVE_PROGRESS` | Save state to `state.json` (0/1). | `1` |
| `RANDOM` | If `1`, randomizes search (non‑sequential). | `0` |
| `ELECTRUM_SEED` | If 1, this turns on Electrum’s seed‑version pre‑filter and adjusts checksum behavior. | `0` |
---


---

## 🔀 How to enable random search
In `.env`, set:
```env
RANDOM=1
```
This makes the loop pick random blocks of the search space instead of a sequential sweep.


## Important

We recommend running the search locally on a dedicated 12× NVIDIA RTX 5090 rig when large amounts of funds are at stake, to minimize risk and keep all sensitive material offline. In this configuration, recovering up to 5 missing words can be feasible within a ~3-year search window (depending on constraints and mode). For a fully air-gapped/offline workflow, disable telegram.py and report.py to prevent any outbound communication.



## 📝 I have a partial word in seed
If you have a few letters from one of the seed words, our cracker lets you use wildcards, for example: `seed seed ?aba ? abandon abandon abandon ? abandon`.

The cracker will then search for words that start with **"aba"** using a **combinational** search strategy. It’s about **25% slower**, but it can reduce your search space by **tens to hundreds of times**.

Another interesting thing is that the Total space will be calculated based on exactly how many words and possible combinations you have, making it the most perfect automatic calculator available. If you have partial portions of your seed, it will calculate exactly how much search space you have.

## 🚀 Running

```bash
python3 main.py
```

The script will:
- Detect GPU via OpenCL
- Compile/load kernel with cache
- Load `addresses.txt`
- Start brute‑forcing

---

## 🧪 Key optimizations (based on the code)

### ⚡ 1. Bit‑level pipeline and on‑device checksum
- 128‑bit seed representation (`memHigh` + `memLow`) avoids string work.
- Expands to ASCII only when needed for HMAC.

### ⚡ 2. 64‑bit PBKDF2/HMAC/SHA512
- SHA‑512 uses native `ulong`, reducing instruction count.
- Pre‑formatted HMAC blocks avoid dynamic loops.

### ⚡ 3. Electrum pre‑filter (seed version)
- Invalid seeds are discarded **before** PBKDF2.

### ⚡ 4. Optimized secp256k1 ECC
- Windowed 8-bit NAF multiply and specialized modular reduction.

### ⚡ 5. Direct address set lookup
- In‑memory set lookup avoids costly string conversions.

---

## 📊 Benchmarks (comparison)

### Electrum (addr/s)
| GPU | Throughput |
|-----|-----------|
| RTX 6000 PRO | **72,000,000** |
| RTX 5090 | **69,000,000** |
| RTX 4090 | **40,000,000** |
| RTX 5080 | **35,000,000** |
| RTX 5070 | **23,000,000** |
| RTX 3090 | **23,000,000** |
| RTX 5060 Ti | **15,000,000** |
| RTX 3070 | **12,000,000** |
| RTX 2080 Ti | **10,000,000** |

### BIP‑39 (seeds/s)
| GPU | Throughput |
|-----|-----------|
| RTX 5090 | **1,000,000** |
| RTX 5080 | **600,000** |
| RTX 4070 Laptop | **150,000** |

---

## 🛠️ Usage tips
- **Best case:** missing words at the end (kernel sweeps low bits first).
- **Pause/resume:** `SAVE_PROGRESS=1` writes `state.json`.
- **Use a small, precise address set** to reduce false positives.

---

## ❓ Quick troubleshooting

### OpenCL not found
```bash
sudo apt install -y nvidia-driver-550 ocl-icd-libopencl1 clinfo
clinfo | head -n 20
```

### Select a specific GPU
```bash
main.py 1 
```
For GPU 1

### Build failing (CL_BUILD_PROGRAM_FAILURE)
- Check `kernel/*.cl`.
- Rebuild without cache: delete `kernel/cache/*.clbin`.

---

## 📦 Fast install (copy & paste)
```bash
sudo apt install git
git clone https://github.com/ipsbruno3/bitcoin-mnemonic-recover/
cd bitcoin-mnemonic-recover
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
python -m pip install -U numpy pyopencl python-dotenv mnemonic rich requests bech32 
python main.py
```











