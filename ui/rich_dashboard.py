from __future__ import annotations
import sys
import time
import random
import threading
from dataclasses import dataclass, field
from collections import deque
from contextlib import contextmanager
from typing import Optional
from rich.console import Group
from rich.align import Align
from rich.console import Console, RenderableType
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)

# ----------------- Funções auxiliares (mantidas iguais) -----------------
def ipsbruno_ascii_text():
    try:
        from pyfiglet import Figlet
        art = Figlet(font="slant").renderText("ipsbruno").rstrip("\n")
    except Exception:
        art = """
\n
\n
\n
  _           _                            
 (_)         | |                           
  _ _ __  ___| |__  _ __ _   _ _ __   ___  
 | | '_ \\/ __| '_ \\| '__| | | | '_ \\ / _ \\ 
 | | |_) \\__ \\ |_) | |  | |_| | | | | (_) |
 |_| .__/|___/_.__/|_|   \\__,_|_| |_|\\___/ 
   | |                                     
   |_|           

💀 Cracking Bitcoin BIP-39/Electrum Wallets 1.0 
🌐 Website: https://ipsbruno.me
📧 E-mail: bsbruno@pm.me

""".strip("\n")
    t = Text()
    colors = ["white"] * 6
    for i, ln in enumerate(art.splitlines()):
        t.append(ln + "\n", style=colors[i % len(colors)])
    return t

def _isatty() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:
        return False

def fmt_int(n: Optional[int | float]) -> str:
    if n is None:
        return "-"
    try:
        return f"{n:,.0f}"
    except Exception:
        return str(n)

def fmt_rate(v: Optional[float], unit: str = "hash/s") -> str:
    if v is None or v != v:
        return "-"
    if v >= 1e9:
        return f"[green]{v/1e9:.2f} G{unit}[/green]"
    if v >= 1e6:
        return f"[green]{v/1e6:.2f} M{unit}[/green]"
    if v >= 1e3:
        return f"[green]{v/1e3:.2f} K{unit}[/green]"
    return f"[bright_magenta]{v:.2f} {unit}[/bright_magenta]"

def fmt_mem_gb(gb: Optional[float]) -> str:
    if gb is None or gb != gb:
        return "-"
    return f"{gb:.1f} GB"

def fmt_dur(seconds: Optional[float]) -> str:
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
        parts.append(f"{h:02d}h")
        parts.append(f"{m:02d}m")
        parts.append(f"{s:02d}s")
    else:
        if h: parts.append(f"{h}h {m:02d}m {s:02d}s")
        elif m: parts.append(f"{m}m {s:02d}s")
        else: parts.append(f"{s}s")
    return " ".join(parts)

class RingLog:
    def __init__(self, max_lines: int = 10, ts: bool = True):
        self._lines = deque(maxlen=max_lines)
        self.ts = ts

    def render(self) -> RenderableType:
        if not self._lines:
            return Text("—\n", style="dim")
        return Text.from_markup("\n".join(self._lines) + "\n")

    def push(self, msg: str) -> None:
        msg = str(msg).rstrip("\n")
        if not msg:
            return
        prefix = time.strftime("%d/%m/%Y %H:%M:%S") + " | " if self.ts else ""
        for ln in msg.splitlines():
            self._lines.append(f"[dim]{prefix}[/dim]{ln}" if self.ts else ln)

import pyopencl as cl
def list_gpu_device():
    platforms = cl.get_platforms()
    if not platforms:
        raise RuntimeError("No OpenCL platform found.")
    for platform in platforms:
        gpus = [d for d in platform.get_devices() if d.type & cl.device_type.GPU]
        if gpus:
            return gpus
    return platforms[0].get_devices()
# ----------------- UIState -----------------
@dataclass
class UIState:
    status: str = "Aguardando…"
    started_at: float = field(default_factory=time.perf_counter)

    build_combinational: Optional[str] = None
    build_seconds: Optional[float] = None
    build_progress: bool = False
    elapsed_init_time: Optional[float] =  time.perf_counter()
    space_current: Optional[int] = None
    space_total: Optional[int] = None
    space_done: Optional[int] = None
    build_mode: Optional[str] = "BIP39"

    device_name: Optional[str] = None
    device_vendor: Optional[str] = None
    device_driver: Optional[str] = None
    device_version: Optional[str] = None
    device_cu: Optional[int] = None
    device_clock_mhz: Optional[int] = None
    device_mem_gb: Optional[float] = None
    
    # ← CORREÇÃO AQUI
    gpu_hash: dict[int, float] = field(default_factory=dict)
    
    @property
    def elapsed(self) -> float:
        return time.perf_counter() - self.started_at

# ----------------- RichDashboard -----------------
class RichDashboard:
    def __init__(self, *, title: str = "Job Dashboard", log_lines: int = 20):
        self.console = Console()
        self.state = UIState()
        self.log = RingLog(max_lines=log_lines)
        self.title = title
        self.encontradoUI = Text()
        self._task_run: Optional[int] = None
        self.progress = Progress(
            SpinnerColumn(style="bold cyan"),
            TextColumn("[bold]{task.description}[/bold]"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            expand=True,
        )

        self._task_build = self.progress.add_task("[bold]Loading OpenCL ...[/bold]", total=1000)

        def animate_build():
            while not self.state.build_progress:
                if self.state.build_progress:
                    break
                self.progress.update(self._task_build, advance=random.randint(2, 5))
                time.sleep(0.2)

        threading.Thread(target=animate_build, daemon=True).start()

        self._live: Optional[Live] = None

    def set_encontrado(self, *, matched):
        if not hasattr(self, "_found_map"):
            self._found_map = {}
            self.encontradoUI = Text.from_markup("\n\n[green]Address Cracked:[/green]\n")

        changed = False
        for ad in matched:
            addr = ad.get("addr", "")
            mn = ad.get("mn", "")
            if not addr:
                continue
            if self._found_map.get(addr) != mn:
                self._found_map[addr] = mn
                changed = True

        if changed:
            linhas = [f"✅ [white]{a}\n{m}[/white]\n\n" for a, m in self._found_map.items()]
            body = Text.from_markup("\n".join(linhas))
            self.encontradoUI = Text.from_markup("\n\n[green]Address Cracked:[/green]\n") + body



    def print5(self, *args, sep=" ", end="") -> None:
        self.log.push(sep.join(str(a) for a in args) + end)

    def _stats_table(self) -> Table:
        s = self.state
        t = Table.grid(padding=(0, 1))
        t.add_column(justify="left", style="dim", width=20, no_wrap=True)
        t.add_column(overflow="fold")

        def section(title: str) -> None:
            t.add_row("", f"[bold]{title}[/bold]")

        t.add_row("", "")
        t.add_row("", "")

        if s.space_total is not None:
            section("------- Time --------")
            done = s.space_done or 0
            elapsed = (time.perf_counter() - s.elapsed_init_time) if s.elapsed_init_time else 0
            avg_rate = (s.space_current or 0) / elapsed if elapsed > 0 else 0

            t.add_row("Total Rate", fmt_rate(avg_rate))
            t.add_row("Total", fmt_int(s.space_total))
            t.add_row("Done", fmt_int(done))

            if avg_rate > 0:
                remaining = max(0, int(s.space_total - done))
                t.add_row("Total ETA", fmt_dur(remaining / avg_rate))
                t.add_row("Remaining", "[blue]Finished[/blue]" if done >= s.space_total else fmt_int(s.space_total - done))
                t.add_row("Elapsed:", fmt_dur(elapsed))
            else:
                t.add_row("ETA", "-")

        t.add_row("", "")
        t.add_row("", "")
        section("------- Info --------")
        t.add_row("Contact", "[green]bsbruno@proton.me[/green]")
        t.add_row("Policy", "[yellow]⛔[/yellow] Never share your seed phrase.\n[yellow]⚠ [/yellow] Authorized recoveries only.")

        if s.space_total is not None:
            t.add_row("", "")
            section("----- Overview -----")
            t.add_row("Mode", f"[green]{s.build_mode or '-'}[/green]")
            t.add_row("Search", f"[blue]{s.build_combinational or '-'}[/blue]")
            t.add_row("GPUS", f"[cyan]{len(list_gpu_device())}[/cyan]")

        section("\n\n----- Benchmarks -----")
        if s.gpu_hash:
            for gpu_id, rate in s.gpu_hash.items():
                t.add_row(f"GPU #{gpu_id}", fmt_rate(rate))
        else:
            t.add_row("Benchmarks", "[dim]Aguardando...[/dim]")

        return t
    def set_benchmark(self, *,gpu_id: int, rate: float) -> None:
        self.state.gpu_hash[gpu_id] = rate
    def get_benchmark(self, *,gpu_id: int) -> None:
        return self.state.gpu_hash[gpu_id] 
    def set_build_done(self, *, seconds: float, combinational: str, build_mode: str) -> None:
        self.state.build_seconds = seconds
        self.state.build_combinational = combinational
        self.state.build_mode = build_mode
        self.progress.update(self._task_build, completed=1000)
        if self._task_run is None:
            self._task_run = self.progress.add_task("[bold]Brute-forcing ..[/bold]", total=None)
            self.progress.remove_task(self._task_build)
        
        self.state.build_progress = True 
    

    def set_space(self, *, total: Optional[int], done: Optional[int], iter: Optional[int]) -> None:
        self.state.space_done = done
        self.state.space_current = iter
        if self._task_run is None:
            self._task_run = self.progress.add_task("[bold]Brute-forcing ..[/bold]", total=total)
        if self.state.space_total is None:
            self.state.space_total = total
            self.state.elapsed_init_time = time.perf_counter()
                
            self.progress.update(self._task_run, completed=iter or done or 0, total=total)
        else:
            self.progress.update(self._task_run, completed=iter or done or 0)

    def _layout(self) -> Layout:
        layout = Layout(name="root")
        layout.split_column(
            Layout(name="mid", ratio=1),
            Layout(name="bottom", size=15),
        )
        layout["mid"].split_row(
            Layout(name="left", ratio=3),
            Layout(name="right", ratio=2),
        )

        left_content = Group(
            Align.left(ipsbruno_ascii_text()),
            self.progress,
            self.encontradoUI
        )
        left = Panel(left_content, title="Progress", border_style="green", box=box.ROUNDED)
        right = Panel(self._stats_table(), title="Stats", border_style="magenta")
        bottom = Panel(self.log.render(), title="Recents logs: ", border_style="yellow")

        layout["left"].update(left)
        layout["right"].update(right)
        layout["bottom"].update(bottom)
        return layout

    @contextmanager
    def live(self, refresh_per_second: int = 1):
        self._live = Live(self._layout(), console=self.console, refresh_per_second=refresh_per_second)
        with self._live:
           yield self

    def refresh(self) -> None:
        if self._live is not None:
            self._live.update(self._layout(), refresh=True)
