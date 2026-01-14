import os
import sys
import time
import struct
import threading
from queue import Queue
from typing import Generator, Optional, Tuple, List


def get_password_bigendian(s: str, encoding="utf-8"):
    b = s.encode(encoding)
    b = b + bytes.fromhex("0000000180")
    b2 = b + b"\x00" * ((-len(b)) % 8)
    words = struct.unpack(f">{len(b2)//8}Q", b2)
    s_len = len(s)
    return ((s_len * 8) + (140 * 8)), words


def leitor_fseek_threads(
    nome_arquivo: str,
    num_threads: int = 24,
    chunk_size: int = 15 * 1024 * 1024,
    scan_bytes: int = 15 * 1024 * 1024,
    batch_lines: int = 20000,
    queue_max_batches: int = 360,
    quantidade: Optional[int] = None,
) -> Generator[Tuple[Tuple[int, tuple], bytes, int], None, None]:
    """
    YIELD:
      (codificada=(length_bits, words_tuple), raw_line_bytes, raw_len_with_newline)

    - raw_line_bytes: bytes crus da linha (sem \\r e sem \\n)
    - raw_len_with_newline: quantos bytes essa linha ocupava no arquivo (inclui \\n ou \\r\\n quando presente)
    """

    if not os.path.exists(nome_arquivo):
        raise FileNotFoundError(f"Arquivo não encontrado: {nome_arquivo}")

    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    fila: "Queue[tuple]" = Queue(maxsize=queue_max_batches)
    stop_event = threading.Event()

    file_size = os.path.getsize(nome_arquivo)
    part_size = file_size // num_threads

    def align_to_next_newline(f, pos: int) -> int:
        if pos <= 0:
            return 0
        f.seek(pos)
        buf = f.read(scan_bytes)
        if not buf:
            return pos
        i = buf.find(b"\n")
        if i < 0:
            return pos
        return pos + i + 1

    def read_until_newline_after_end(f, end_pos: int) -> bytes:
        f.seek(end_pos)
        buf = f.read(scan_bytes)
        if not buf:
            return b""
        i = buf.find(b"\n")
        if i < 0:
            return buf
        return buf[: i + 1]

    def worker(tid: int, start: int, end: int):
        try:
            with open(nome_arquivo, "rb", buffering=0) as f:
                if start != 0:
                    start = align_to_next_newline(f, start)

                tail = read_until_newline_after_end(f, end)
                end_plus = end + len(tail)

                f.seek(start)
                buf = b""
                batch: List[tuple] = []
                bytes_local = 0
                pos = start

                while not stop_event.is_set() and pos < end_plus:
                    to_read = min(chunk_size, end_plus - pos)
                    chunk = f.read(to_read)
                    if not chunk:
                        break

                    bytes_local += len(chunk)
                    buf += chunk

                    parts = buf.split(b"\n")
                    buf = parts[-1]

                    for line_with_possible_cr in parts[:-1]:
                        if line_with_possible_cr.endswith(b"\r"):
                            raw_line = line_with_possible_cr[:-1]
                            raw_len_with_newline = len(raw_line) + 2  # \r\n
                        else:
                            raw_line = line_with_possible_cr
                            raw_len_with_newline = len(raw_line) + 1  # \n

                        batch.append((raw_line, raw_len_with_newline))

                        if len(batch) >= batch_lines:
                            fila.put(("batch", tid, batch, bytes_local))
                            batch = []
                            bytes_local = 0

                    pos = f.tell()
                if buf:
                    if buf.endswith(b"\r"):
                        raw_line = buf[:-1]
                        raw_len_with_newline = len(raw_line) + 1  # raro, mas considera \r sozinho como 1
                    else:
                        raw_line = buf
                        raw_len_with_newline = len(raw_line)  # EOF sem newline
                    batch.append((raw_line, raw_len_with_newline))

                if batch:
                    fila.put(("batch", tid, batch, bytes_local))

        except Exception as e:
            fila.put(("err", tid, repr(e)))
        finally:
            fila.put(("done", tid))

    threads = []
    for i in range(num_threads):
        start = i * part_size
        end = file_size if i == num_threads - 1 else (i + 1) * part_size
        t = threading.Thread(target=worker, args=(i, start, end), daemon=True)
        threads.append(t)
        t.start()

    done_count = 0
    total_linhas = 0
    total_bytes = 0
    t0 = time.time()
    last_print = t0
    last_lines = 0

    try:
        while done_count < num_threads and not stop_event.is_set():
            msg = fila.get()
            kind = msg[0]

            if kind == "batch":
                _, tid, items, bytes_local = msg

                for raw_line, raw_len_with_newline in items:
                    s = raw_line.decode("utf-8", errors="ignore")
                    codificada = get_password_bigendian(s)
                    yield codificada, raw_line, raw_len_with_newline

                    total_linhas += 1
                    if quantidade and total_linhas >= quantidade:
                        stop_event.set()
                        break

                total_bytes += int(bytes_local)

                now = time.time()
                if now - last_print >= 0.5:
                    dt = now - last_print
                    dlines = total_linhas - last_lines
                    lps = dlines / dt if dt > 0 else 0.0
                    mbs = (total_bytes / (now - t0)) / (1024 * 1024) if now > t0 else 0.0
                    last_print = now
                    last_lines = total_linhas

            elif kind == "err":
                _, tid, err = msg

            elif kind == "done":
                done_count += 1

    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=1)

        dt = time.time() - t0
