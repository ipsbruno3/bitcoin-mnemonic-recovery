
import os
import time
import random
import hashlib
import struct
import threading
import numpy as np
from time import perf_counter
import pyopencl as cl
from dotenv import load_dotenv

from mnemonic import Mnemonic
import wnaf
import mnem
from rbloom import Bloom
import tag64
import re
from concurrent.futures import ThreadPoolExecutor
import reports
import slots
import bloom_filter
import utils
from pathlib import Path

load_dotenv()
# ----------------- Global Configuration -----------------
bf = Bloom(expected_items=10_000_000_000, false_positive_rate=0.001)
wordlist = Mnemonic("english").wordlist
os.environ['PYOPENCL_COMPILER_OUTPUT'] = '1'

SEED = os.getenv("SEED", "")
PASSWORD = os.getenv("PASSWORD", "")
BRUTE_PASSWORD_NOT_SEED = os.getenv("BRUTE_PASSWORD_NOT_SEED", "")
GPU_THREADS = int(os.getenv("GPU_THREADS", 32_000)) - (int(os.getenv("GPU_THREADS", 32_000)) % 64)
MAX_HITS = 5 
WORKGROUP_SIZE = os.getenv("WORKERS")
IS_ELECTRUM = int(os.getenv("ELECTRUM_SEED", 0))
RANDOM_MODE = int(os.getenv("RANDOM", 0))
WNAF_W = 2
NAFS = wnaf.gen_precomputed_table(WNAF_W)
HIT_DTYPE = np.dtype([('widx', '<u2', (12,)), ('tag64', '<u8')])
TEST_DTYPE = np.dtype([("mnemo",   np.uint8, (128,)),("address", np.uint8, (92,)),], align=False)
GLOBAL_SLOT_INFO = {'job_id': 0, 'checkpoint_pos': 0}
global_rates = {}
import hashlib, unicodedata
from embit import bip39, bip32, script
from embit.networks import NETWORKS

def _nfkd(s: str) -> str:
    return unicodedata.normalize("NFKD", s or "")

def _electrum_v2_seed(mnemonic: str, passphrase: str = "") -> bytes:
    pw = _nfkd(" ".join(mnemonic.strip().lower().split())).encode("utf-8")
    salt = (_nfkd("electrum") + _nfkd(passphrase)).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", pw, salt, 2048, dklen=64)

def derive_addr_python(mnemonic: str, is_electrum: bool, passphrase: str = "") -> str:
    mnemonic = " ".join(mnemonic.strip().lower().split())

    if is_electrum:
        seed = _electrum_v2_seed(mnemonic, passphrase)
        root = bip32.HDKey.from_seed(seed)
        node = root.derive("m/0h/0/0").to_public()
    else:
        seed = bip39.mnemonic_to_seed(_nfkd(mnemonic), _nfkd(passphrase))
        root = bip32.HDKey.from_seed(seed)
        node = root.derive("m/84h/0h/0h/0/0").to_public()

    return script.p2wpkh(node.key).address(NETWORKS["main"])  # bc1...


total_search_space = 0
queue_lock = threading.Lock()
ui_lock = threading.Lock()
counter_lock = threading.Lock()
state_lock = threading.Lock()
bloom_lock = threading.Lock()
hits_lock = threading.Lock()
VAST_AI_ID=False
ui = None  
counter_global = 0
counterEachVerification=0


# ----------------- Helper Functions -----------------
def get_pbkdf_password_hex(password: str):
    data = password.encode()
    padded = data + bytes.fromhex("0000000180") + b"\x00" * ((-len(data)) % 8)
    words = struct.unpack(f">{len(padded)//8}Q", padded)
    lines = [f"inner_data[{i+17}] = 0x{w:016X}UL;" for i, w in enumerate(words)]
    lines.append(f"inner_data[31] = {len(password)*8 + 140*8}UL;")
    return "\n".join(lines)

def compute_kernel_hash():
    files = []
    kernel_dir = "./kernel"
    if os.path.isdir(kernel_dir):
        files = [os.path.join(kernel_dir, f) for f in os.listdir(kernel_dir) if f.endswith((".cl", ".h"))]
    main_kernel = "./kernel/main.cl"
    if os.path.isfile(main_kernel) and main_kernel not in files:
        files.append(main_kernel)
    files.sort()

    env_content = ""
    if os.path.isfile(".env"):
        with open(".env", "rb") as f:
            env_content = f.read().decode(errors="ignore")
            if PASSWORD:
                env_content = env_content.replace("#define BIG_ENDIAN_PASSWORD", get_pbkdf_password_hex(PASSWORD))
        env_hash = hashlib.sha1(env_content.encode()).hexdigest()
    else:
        env_hash = "no_env"

    hasher = hashlib.sha1()
    for path in files:
        with open(path, "rb") as f:
            hasher.update(f.read())
    hasher.update(env_hash.encode())
    return hasher.hexdigest()



def build_program(ctx, dev, combinational=False):
    src_hash = compute_kernel_hash()
    dev_tag = re.sub(r"[^A-Za-z0-9_.-]+", "_", dev.name.strip())
    utils.log("mode", f"Building application ...")
    
    os.makedirs("./kernel/cache", exist_ok=True)
    cache_path = f"./kernel/cache/main.{dev_tag}.{dev.idx}-{src_hash}.clbin"

    options = [f"-DWNAF_W={WNAF_W}", "-cl-fast-relaxed-math"]
    if IS_ELECTRUM: options.append("-DELECTRUM_SEED=1")
    if combinational: options.append("-DCOMBINATIONAL=1")
    if BRUTE_PASSWORD_NOT_SEED: options.append("-DBRUTE_PASSWORD_NOT_SEED=1")
    options.append("-DCACHE="+str(round(time.time())))
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                binary = f.read()
            prog = cl.Program(ctx, [dev], [binary]).build(options=options)
            utils.log("cache", f"Loaded successfully: {cache_path}")
            return prog
        except Exception as e:
            utils.log("cache", f"Failed to load, recompiling... ({e})")

    with open("./kernel/main.cl", "r", encoding="utf-8") as f:
        src = f.read()
        if PASSWORD:
            src = src.replace("#define BIG_ENDIAN_PASSWORD", get_pbkdf_password_hex(PASSWORD))
        prog = cl.Program(ctx, src).build(options=options)

        try:
            if prog.binaries and prog.binaries[0]:
                with open(cache_path, "wb") as f:
                    f.write(prog.binaries[0])
                utils.log("cache", f"Saved: {cache_path}")
        except Exception as e:
            utils.log("cache", f"Failed to save: {e}")

        return prog

def list_gpu_devices():
    devs, idx = [], 0
    for p in [cl.get_platforms()[0]]:
        for d in p.get_devices(device_type=cl.device_type.GPU):
            try: d.idx = idx
            except: pass
            devs.append(d)
            idx += 1
    if not devs:
        raise RuntimeError("No OpenCL device found.")
    return devs




def prepare_seed_data():
    missing_count, _ = mnem.count_placeholders(SEED, placeholder="?")
    combinations, combo_sizes, is_combinational = mnem.get_bip39_combinations(SEED.strip().lower().split(' '), wordlist)
    if not mnem.is_checksum_verification(SEED):
        is_combinational = True

    fixed_words = mnem.replace_placeholder(SEED).strip().split()
    lens_array = np.asarray(combo_sizes, dtype=np.uint32)
    seeds_array = np.ascontiguousarray(np.asarray(combinations, dtype=np.uint32).reshape(-1))

    total_combos = lens_array.copy()
    checksum_limit = 128 * (16 if IS_ELECTRUM else 1)
    if not IS_ELECTRUM and total_combos[11] > 128:
        total_combos[11] = 128
    total_search_space = int(np.prod(total_combos))

    return fixed_words, seeds_array, lens_array, is_combinational, missing_count, total_search_space, checksum_limit



def create_buffers(ctx,bip39_seeds,bip39_lens):
    nafs_buffer = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=NAFS)
    dummy = cl.Buffer(ctx, cl.mem_flags.READ_ONLY, size=8)

    if BRUTE_PASSWORD_NOT_SEED:
        seed_buffer = dummy
        lens_buffer = dummy
    else:
        seed_buffer = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=bip39_seeds)
        lens_buffer = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=bip39_lens)

    return nafs_buffer, seed_buffer, lens_buffer, dummy


def run_kernel(gpu,ctx,queue,bf_buf,bf_mask,bf_words_mask,kernel,dummy_buffer,high, low, index, addr_buffer, addr_size, nafs_buffer,
               seed_buffer, lens_buffer, wordlist_buffer=None, wordlist_size=0):
  
    hits_buf = cl.Buffer(ctx, cl.mem_flags.READ_WRITE, size=HIT_DTYPE.itemsize)
    test_buf = cl.Buffer(ctx, cl.mem_flags.READ_WRITE, size=TEST_DTYPE.itemsize)
    count_buf = cl.Buffer(ctx, cl.mem_flags.READ_WRITE, size=4)

    cl.enqueue_fill_buffer(queue, count_buf, np.uint32(0), 0, 4).wait()
    seed_buffer = seed_buffer or dummy_buffer
    lens_buffer = lens_buffer or dummy_buffer
    wordlist_buffer = wordlist_buffer or dummy_buffer

    kernel.set_args(
        test_buf,
        np.uint64(low + index),
        np.uint64(high),
        addr_buffer,
        np.uint32(addr_size),
        nafs_buffer,
        seed_buffer,
        lens_buffer,
        wordlist_buffer,
        np.uint32(wordlist_size),
        hits_buf,
        count_buf,
        bf_buf,
        np.uint32(bf_mask),
        np.uint32(bf_words_mask)
    
    )
    cl.enqueue_nd_range_kernel(queue, kernel, (GPU_THREADS,), (WORKGROUP_SIZE,)).wait()

    def process_hits():
        global counterEachVerification
        count = np.empty(1, dtype=np.uint32)
        cl.enqueue_copy(queue, count, count_buf).wait()


        test = np.empty(1, dtype=TEST_DTYPE)
        cl.enqueue_copy(queue, test, test_buf).wait()
        t = test[0]
        mn = bytes(t["mnemo"]).split(b"\0", 1)[0].decode("utf-8", "ignore").strip()
        addr_k = bytes(t["address"]).split(b"\0", 1)[0].decode("utf-8", "ignore").strip()

        addr_py = derive_addr_python(mn, bool(IS_ELECTRUM), PASSWORD)

        if addr_py != addr_k:
            utils.log("error", f"Address mismatch!\nKernel: {addr_k}\nPython: {addr_py}\nMN: {mn}")
            raise ValueError("Address mismatch")
        else:
            if(counterEachVerification%100==0):
                utils.log("success", f"Address match OK: {addr_py}. First word: {mn.split()[0]} | GPU#{gpu.idx} {gpu.name.strip()}")
            counterEachVerification +=1

            
        hit_count = min(int(count[0]), MAX_HITS)
        if( hit_count == 0):
            return
        hits = np.empty(hit_count, dtype=HIT_DTYPE)
        cl.enqueue_copy(queue, hits, hits_buf).wait()

        for hit in hits:
            mnemonic_full, mnemonic_display = mnem.changeSeed(hit["widx"])
            address = int(hit["tag64"])
            utils.log("hit", f"Found! → {mnemonic_display}")
            with utils.ui_lock:
                reports.report_hit(gpu.uuid, address, mnemonic_full)
                utils.ui.set_encontrado(matched=[{"addr": f"{hit['tag64']:x}", "mn": mnemonic_display}])
            try:
                hit["widx"].fill(0)
            except Exception:
                pass
    threading.Thread(target=process_hits, daemon=True).start()

def generate_random_unique(start, end):
    with bloom_lock: 
        while True:
            candidate = random.randint(start, end)
            key = str(candidate).encode()
            if key not in bf:
                bf.add(key)
                return candidate



def send_periodic_reports():
    global global_rates
    while True:
        time.sleep(5)
        if global_rates:
            reports.update_hashrates_batch(global_rates)
            global_rates = {}

threading.Thread(target=send_periodic_reports, daemon=True).start()



def run_force(device, ctx, queue,bf_buf,bf_mask,bf_words_mask, kernel, dummy_buffer, high, low, chunk_size, start_index, missing_count, checksum_limit,
              addr_buffer, addr_size, nafs_buffer, seed_buffer, lens_buffer,job,checkpoint_pos):
    global counter_global, counterEachVerification
    current = start_index
    global global_rates
    chunk_end = start_index + chunk_size - 1
    scanned = 0
    last_update = time.time()
    first_update = time.time()
    first_run = False

    if(counterEachVerification%100==0):
        utils.log("mode", f"GPU {device.idx}# {device.name} → Range [{start_index:,} até {chunk_end:,}] = {chunk_size:,} combinações")
    
    while True:
        if RANDOM_MODE:
            index = generate_random_unique(start_index, chunk_end)
        else:
            index = current
        run_kernel(device, ctx, queue,bf_buf,bf_mask,bf_words_mask, kernel, dummy_buffer, high, low+(job*slots.CHUNK_SIZE), index, 
                   addr_buffer, addr_size, nafs_buffer, seed_buffer, lens_buffer)
        scanned += GPU_THREADS
        counter_global += GPU_THREADS
        checkpoint_pos += GPU_THREADS
        elapsed = time.time() - first_update
        rate = scanned / elapsed if elapsed > 0 else 0.0
        
        with utils.ui_lock :
            utils.ui.set_space(total=total_search_space, done=counter_global, iter=counter_global)
            utils.ui.set_benchmark(gpu_id=device.idx, rate=rate)
            global_rates[device.idx] = rate
            utils.ui.refresh()
        
        if time.time() - last_update > 60 or (not first_run and time.time() - last_update > 20):
            last_update = time.time()
            first_run = True
            utils.log("benchmark", f" [brown]GPU[/brown] {device.idx} → Current speed: [green]{rate:,.2f}[/green] seeds/s | [blue]Total: {scanned:,} seeds[/blue]")
            if not RANDOM_MODE :
                with state_lock:
                    slots.upsert_slot(job,state="running", checkpoint_pos=checkpoint_pos,updated_at=time.time())

 
        if not RANDOM_MODE:
            current += GPU_THREADS
            if current > chunk_end:
                utils.log("success", f"GPU {device.idx} completou chunk ({scanned:,} processados)")
                break





def startup_gpu(device, offset, chunk_size, fixed_words, bip39_seeds, bip39_lens, is_combinational, missing_count, total_search_space, checksum_limit,job,checkpoint_pos):
    utils.log("mode", f"🚀 Starting GPU {device.vendor}: {device.name.strip()}")
   
    ctx = cl.Context([device])
    name = device.name.strip()
    vendor = device.vendor.strip()
    driver_version = device.driver_version.strip()

    hash_input = f"{device.idx}{device.name}{device.vendor}{device.vendor_id}{device.driver_version}"

    reports.gpu_uuids[device.idx] = str(VAST_AI_ID)+hash_input
    reports.register(reports.gpu_uuids[device.idx] , name, vendor, driver_version)
    device.uuid = reports.gpu_uuids[device.idx]
    
    nafs_buffer, seed_buffer, lens_buffer, dummy_buffer = create_buffers(ctx, bip39_seeds, bip39_lens)
    queue = cl.CommandQueue(ctx, properties=cl.command_queue_properties.PROFILING_ENABLE)
    
    program = build_program(ctx, device, combinational=is_combinational)
    kernel = program.verify
    
    mode = ("Wordlist" if BRUTE_PASSWORD_NOT_SEED else
            "Random" if RANDOM_MODE else
            "Combinational" if is_combinational else "Sequential")

    if device.idx == 0:
        with utils.ui_lock:
            utils.ui.set_build_done(seconds=perf_counter() - build_start, combinational=mode,
                              build_mode="Electrum" if IS_ELECTRUM else "BIP39")
            utils.ui.set_space(total=total_search_space, done=0, iter=0)
    
    utils.log("opencl", f"GPU {device.idx} → Kernel compiled successfully!")

    tags_buf, tags_n, tags_host = tag64.load_target_addresses(ctx) 
    bf_u32, bf_mask, bf_words_mask = bloom_filter.build_bloom_u32(tags_host, nbits_pow2=1<<27, k=4)
    bf_buf = bloom_filter.upload_bloom(ctx, bf_u32)
    high, low = mnem.mnemonic_to_uint64_pair(mnem.words_to_indices(fixed_words))
    
    start_index = offset

    if is_combinational and missing_count > 3:
        utils.log("tip", "Sequential search without middle wildcards is much faster!")
 
    run_force(device, ctx, queue,bf_buf,bf_mask,bf_words_mask, kernel, dummy_buffer, high, low, chunk_size, start_index, 
                  missing_count, checksum_limit, tags_buf, tags_n, nafs_buffer, 
                  seed_buffer, lens_buffer, job,checkpoint_pos)


if __name__ == "__main__":
    utils.initialize_ui()
 
    
    build_start = perf_counter()
    VAST_AI_ID = os.environ.get("CONTAINER_ID")
    job=0
    checkpoint_pos=0
    mnem.set_redaction([i for i,w in enumerate(SEED.split()) if w.startswith("?")])
    if not RANDOM_MODE and os.getenv("SLOT_API_URL","")!="":
        GLOBAL_SLOT_INFO=slots.pick_slot()
        if "job_id" in GLOBAL_SLOT_INFO:
            job=int(GLOBAL_SLOT_INFO["job_id"])
            checkpoint_pos=int(round(float(GLOBAL_SLOT_INFO["checkpoint_pos"])))
            utils.log("mode",f'Stride ID: 🎰 [red]Chunk ID[/red]  {job}') 
            utils.log("checkpoint",f' Checkpoint position ⏱️: [red]Pos[/red]  {checkpoint_pos:,}')
            slots.upsert_slot(job, state="running",
                start_pos=job*slots.CHUNK_SIZE,
                end_pos=(job+1)*slots.CHUNK_SIZE,
                chunk_size=slots.CHUNK_SIZE,
                checkpoint_pos=checkpoint_pos,
                updated_at=int(time.time())
            )
        else:
            job = random.randint(0,2048)            
            checkpoint_pos=0
            slots.CHUNK_SIZE=10_000_000
            utils.log("mode",f'Stride ID: 🎰 [red]Chunk ID[/red]  {job}') 
            utils.log("checkpoint",f' Checkpoint position ⏱️: [red]Pos[/red]  {checkpoint_pos:,}')
    if os.getenv("SLOT_API_URL","") == "":
        utils.log("warning", "SLOT_API_URL is not set in .env! Checkpoints or reports will not be work")
    if int(job) < 0:
        utils.log("error","Not found any disponivel slot, trying random mode!") 
        RANDOM_MODE = 1
    if SEED == "" and os.getenv("H"):
        SEED = mnem.uint64_pair_to_phrase(int(os.getenv("H")), int(os.getenv("L")))
        if os.getenv("MISSING_WORDS"):
            num = int(os.getenv("MISSING_WORDS"))
            words = SEED.split()
            words[-num:] = ["?"] * num
            SEED = " ".join(words)
    fixed_words, bip39_seeds, bip39_lens, is_combinational, missing_count, search_space, checksum_limit = prepare_seed_data()

    gpus = list_gpu_devices()
    num_gpus = len(gpus) 
    if slots.CHUNK_SIZE > search_space and not RANDOM_MODE:
        slots.CHUNK_SIZE = search_space
    total_search_space = slots.CHUNK_SIZE - checkpoint_pos 
    if RANDOM_MODE:
        total_search_space = search_space
    offsets = [0] * num_gpus
    chunk_sizes = [0] * num_gpus
    current_offset = 0
    base_chunk = total_search_space // num_gpus
    remain = total_search_space % num_gpus
    for i in range(num_gpus):
        chunk_sizes[i] = base_chunk + (1 if i < remain else 0)
        offsets[i] = current_offset
        current_offset += chunk_sizes[i]

    utils.log("addresses", f"Loaded → [green]{search_space:,}[/green] possible combinations")
    utils.log("checkpoint", f"Percentage: [green]{(100-(total_search_space/slots.CHUNK_SIZE)*100):.2f}%[/green] (this run stride)")
    utils.log("mode", f"[red]Random:[/red][white] {RANDOM_MODE} | [cyan]GPUs:[/cyan][white] {num_gpus} | [/white][green]Space[/green][white]: {search_space:,} | [/white][yellow]Combinational[/yellow][white]: {is_combinational} | [/white][magenta]Missing[/magenta][white]: {missing_count} words | [/white] [blue]Electrum: [/blue] {IS_ELECTRUM}")
    
    with utils.ui.live():
        with ThreadPoolExecutor(max_workers=num_gpus) as executor:
            futures = []
            for gpu in gpus:
                futures.append(
                    executor.submit(
                        startup_gpu,
                        gpu, offsets[gpu.idx], chunk_sizes[gpu.idx],
                        fixed_words, bip39_seeds, bip39_lens,
                        is_combinational, missing_count, total_search_space, checksum_limit,job, checkpoint_pos
                    )
                )
            for future in futures:
                try:
                    future.result() 
                except Exception as e:
                    utils.log("error", f"Erro em GPU: {e}")
                    import traceback
                    traceback.print_exc()
    utils.log("total", "Processamento concluído.")
