import requests
import os
import time
from typing import Dict, Any 
from dotenv import load_dotenv
load_dotenv() 
SLOT_API_URL = os.getenv("SLOT_API_URL", "").strip()

HEADERS = {
    "Content-Type": "application/json"
}

gpu_uuids: Dict[int, str] = {} 

def request(endpoint: str, data: Dict[str, Any], retries: int = 1, base_delay: int = 30) -> bool:
    if not SLOT_API_URL:
        return False
    url = f"{SLOT_API_URL.rstrip('/')}{endpoint}"
    for attempt in range(retries):
        try:
            r = requests.post(url, json=data, headers=HEADERS, timeout=20)
            r.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            error_msg = f"[ERROR] {endpoint} (tentativa {attempt+1}/{retries}): {e}"
            if hasattr(e, 'response') and e.response:
                error_msg += f" | {e.response.status_code} - {e.response.text.strip()}"
            if attempt < retries - 1:
                delay = base_delay * (2 ** attempt)  #
                time.sleep(delay)
    return False

def register(uuid: str, name: str, vendor: str, driver_version: str, hash_rate: float = 0.0) -> bool:
    data = {
        "uuid": uuid,
        "name": name or "Unknown",
        "vendor": vendor or "Unknown",
        "driver_version": driver_version or "Unknown",
        "hash_rate": hash_rate
    }
    return request("/register-device", data, retries=3, base_delay=5)

def update_hashrates_batch(hashrates: Dict[int, float]) -> bool:
    if not hashrates:
        return True
    devices = [{"uuid": gpu_uuids[gpu_id], "hash_rate": rate} for gpu_id, rate in hashrates.items() if rate > 0 and gpu_id in gpu_uuids]
    if not devices:
        return True
    data = {"devices": devices}
    return request("/update-hashrates", data, retries=2, base_delay=10)

def report_hit(uuid: str, address: Any, mnemonic: str) -> bool:
    addr_str = hex(address) if isinstance(address, int) else str(address)
    if isinstance(address, int):
        addr_str = f"0x{addr_str[2:]}"  
    data = {
        "uuid": uuid,
        "address": addr_str,
        "mnemonic": mnemonic
    }
    return request("/report-hit", data, retries=1000, base_delay=30)