# ----------------- Standardized Logging -----------------
import time 
import threading
from ui.rich_dashboard import RichDashboard

file_lock = threading.Lock()
ui_lock = threading.Lock()
ui = None
def gpu_tag(dev):
    return f"GPU#{getattr(dev,'idx','?')} {getattr(dev,'name','?').strip()}"

def initialize_ui():
    global ui
    ui = RichDashboard()

TAG_COLORS = {
    "cache": "bold green",
    "opencl": "bold blue",
    "addresses": "bold magenta",
    "hit": "bold red on white",
    "address": "bold cyan",
    "mode": "bold cyan",
    "file": "bold yellow",
    "error": "bold red",
    "checkpoint": "bold green",
    "warning": "bold yellow",
    "info": "bold blue",
    "tip": "bold yellow",
    "success": "bold white on green",
    "total": "bold magenta",
}

def log(tag: str, message: str):
    color = TAG_COLORS.get(tag.lower(), "white")
    formatted_tag = tag.capitalize()
    with ui_lock:
        ui.print5(f"[{color}]{formatted_tag}[/{color}] {message}")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    file_line = f"[{timestamp}] [{tag.upper()}] {message}"
    with file_lock:
        try:
            with open("logs.txt", "a", encoding="utf-8") as f:
                f.write(file_line + "\n")
        except:
            pass