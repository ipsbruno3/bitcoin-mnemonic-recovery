import os
import time
import requests
from html import escape as html_escape
import utils
_session = requests.Session()

def plain_rate(v: float | None, unit: str = "hash/s") -> str:
    if v is None or v != v or v <= 0:
        return "-"
    if v >= 1e9:
        return f"{v/1e9:.2f} G{unit}"
    if v >= 1e6:
        return f"{v/1e6:.2f} M{unit}"
    if v >= 1e3:
        return f"{v/1e3:.2f} K{unit}"
    return f"{v:.2f} {unit}"

def plain_int(n: int | float | None) -> str:
    if n is None:
        return "-"
    try:
        return f"{n:,.0f}"
    except Exception:
        return str(n)

def plain_dur(seconds: float | None) -> str:
    if seconds is None or seconds != seconds:
        return "-"
    seconds = max(0.0, float(seconds))
    YEAR = 365 * 24 * 3600
    MONTH = 30 * 24 * 3600
    WEEK = 7 * 24 * 3600
    DAY = 24 * 3600
    HOUR = 3600
    MIN = 60
    y = int(seconds // YEAR); seconds -= y * YEAR
    mo = int(seconds // MONTH); seconds -= mo * MONTH
    w = int(seconds // WEEK); seconds -= w * WEEK
    d = int(seconds // DAY); seconds -= d * DAY
    h = int(seconds // HOUR); seconds -= h * HOUR
    m = int(seconds // MIN); seconds -= m * MIN
    s = int(seconds)
    parts = []
    if y: parts.append(f"{y}y")
    if mo: parts.append(f"{mo}mo")
    if w: parts.append(f"{w}w")
    if d: parts.append(f"{d}d")
    if parts:
        parts.append(f"{h:02d}h {m:02d}m {s:02d}s")
    else:
        if h: parts.append(f"{h}h {m:02d}m {s:02d}s")
        elif m: parts.append(f"{m}m {s:02d}s")
        else: parts.append(f"{s}s")
    return " ".join(parts)

def send_telegram_message(msg: str, parse_mode: str = "HTML") -> bool:
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("USER_ID")
    if not token or not chat_id:
        utils.log("Erro Telegram: TOKEN ou USER_ID não configurados")
        return False
    if len(msg) > 4000:
        msg = msg[:3990] + "\n\n<i>(mensagem truncada)</i>"
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": msg, "parse_mode": parse_mode, "disable_web_page_preview": True}
    try:
        r = _session.post(url, json=payload, timeout=15)
        r.raise_for_status()
        data = r.json()
        utils.log(data)
        return True
    except Exception as e:
        utils.log(f"Erro ao enviar Telegram: {e}")
        return False

def send_hit_message(addr, mn: str, dev_tag: str = "") -> bool:
    addr_str = hex(addr) if isinstance(addr, int) else str(addr)
    addr_str = html_escape(addr_str)
    mn = html_escape(str(mn))
    dev = html_escape(dev_tag.upper()) if dev_tag else "GPU"
    mensagem = (
        f"🔥 <b>HIT ENCONTRADO!</b> 🔥\n\n"
        f"🖥️ <b>{dev}</b>\n"
        f"<b>✅ Endereço/Tag:</b> <code>{addr_str}</code>\n"
        f"<b>🔏 Mnemonic/Seed:</b> <code>{mn}</code>\n\n"
        f"🕒 {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    return send_telegram_message(mensagem)

def send_telegram_startup_message(dev_tag: str) -> bool:
    dev_tag = html_escape(dev_tag)
    msg = (
        f"🖥️ <b>{dev_tag.upper()}</b>\n"
        f"🚀 GPU STARTED\n"
        f"🕗 <b>Início:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    return send_telegram_message(msg)

def send_telegram_benchmark(ui, dev_tag: str = "") -> bool:
    if ui is None:
        return False    
    s = ui.state
    elapsed = time.perf_counter() - s.elapsed_init_time
    if elapsed < 0.1:
        return False      
    current = s.space_current or s.space_done or 0
    avg_rate = current / elapsed if elapsed > 0 else 0.0
    bench_lines = []
    for gpu_id in sorted(s.gpu_hash.keys()):
        rate = s.gpu_hash.get(gpu_id, 0.0)
        bench_lines.append(f"• GPU {gpu_id}: {plain_rate(rate)}")
    bench_lines.append(f"• <b>Total:</b> {plain_rate(avg_rate)}")
    bench_str = "\n".join(bench_lines)
    if s.space_total is None or s.space_total <= 0:
        scanned_str = plain_int(current)
        eta_str = "∞"
    else:
        scanned_str = f"{plain_int(current)} / {plain_int(s.space_total)}"
        remaining = max(0, s.space_total - current)
        eta = remaining / avg_rate if avg_rate > 0 else float('inf')
        eta_str = plain_dur(eta) if eta < float('inf') else "∞"
    dev = f"<b>{html_escape(dev_tag.upper())}</b>\n" if dev_tag else ""
    msg = (
        f"📊 <b>BENCHMARK / STATUS</b>\n"
        f"{dev}\n"
        f"⏱️ <b>Tempo decorrido:</b> {plain_dur(elapsed)}\n"
        f"🔢 <b>Escaneado:</b> {scanned_str}\n"
        f"⏳ <b>ETA:</b> {eta_str}\n\n"
        f"📋 <b>Hashrates:</b>\n{bench_str}\n\n"
        f"🕒 {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    return send_telegram_message(msg)