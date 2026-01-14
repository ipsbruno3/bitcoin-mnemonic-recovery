#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
import math
import argparse
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import requests

HOURS_PER_MONTH = 730
DEFAULT_STATE_PATH = "vast_bids.json"


# -------------------------
# Vast API wrapper
# -------------------------
class VastAPI:
    def __init__(self, api_key: str, base_url: str = "https://console.vast.ai/api/v0", timeout: int = 60):
        if not api_key:
            raise ValueError("VAST_API_KEY não definido (export VAST_API_KEY=...)")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
        )

    def _req(self, method: str, path: str, *, json_body: Optional[dict] = None) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        for attempt in range(5):
            r = self.session.request(method, url, json=json_body, timeout=self.timeout)
            # backoff leve em rate limit
            if r.status_code == 429 and attempt < 4:
                time.sleep(1.0 + attempt * 1.5)
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError("Falha após retries")

    # Search offers: POST /api/v0/bundles/
    def search_offers(self, body: Dict[str, Any]) -> List[Dict[str, Any]]:
        data = self._req("POST", "bundles/", json_body=body)
        offers = data.get("offers", [])
        if isinstance(offers, dict):
            offers = [offers]
        return offers

    # Create instance: PUT /api/v0/asks/{id}/
    def create_instance(self, ask_id: int, body: Dict[str, Any]) -> int:
        data = self._req("PUT", f"asks/{ask_id}/", json_body=body)
        if not data.get("success"):
            raise RuntimeError(f"create_instance falhou: {data}")
        # new_contract = instance_id
        return int(data["new_contract"])

    # List instances: GET /api/v0/instances/
    def list_instances(self) -> List[Dict[str, Any]]:
        data = self._req("GET", "instances/")
        return data.get("instances", [])

    # Show instance: GET /api/v0/instances/{id}/
    def get_instance(self, instance_id: int) -> Dict[str, Any]:
        data = self._req("GET", f"instances/{instance_id}/")
        inst = data.get("instances", {})
        return inst

    # Attach SSH key: POST /api/v0/instances/{id}/ssh/
    def attach_ssh_key(self, instance_id: int, public_key_str: str) -> None:
        body = {"ssh_key": public_key_str.strip()}
        data = self._req("POST", f"instances/{instance_id}/ssh/", json_body=body)
        if not data.get("success"):
            raise RuntimeError(f"attach_ssh_key falhou: {data}")

    # Execute command (sem SSH): PUT /api/v0/instances/command/{id}/
    def execute(self, instance_id: int, command: str) -> Dict[str, Any]:
        body = {"command": command}
        return self._req("PUT", f"instances/command/{instance_id}/", json_body=body)


# -------------------------
# Persistent state file
# -------------------------
def load_state(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"instances": {}}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_state(path: str, state: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, path)

def upsert_instance(state: Dict[str, Any], inst: Dict[str, Any]) -> None:
    state.setdefault("instances", {})
    iid = str(inst["id"])
    cur = state["instances"].get(iid, {})
    cur.update(inst)
    cur["last_seen_ts"] = time.time()
    state["instances"][iid] = cur


# -------------------------
# Ranking helpers
# -------------------------
def safe_float(x: Any) -> float:
    try:
        if x is None:
            return float("nan")
        return float(x)
    except Exception:
        return float("nan")

def compute_value_row(offer: Dict[str, Any], *, hourly_price: Optional[float] = None) -> Optional[Dict[str, Any]]:
    tflops = safe_float(offer.get("total_flops"))
    if not math.isfinite(tflops) or tflops <= 0:
        return None

    # Para on-demand, use dph_total. Para bid, muitas vezes faz sentido olhar min_bid.
    dph_total = safe_float(offer.get("dph_total"))
    min_bid = safe_float(offer.get("min_bid"))

    # escolha do preço/h assumido:
    if hourly_price is not None:
        hourly = hourly_price
    else:
        # preferir dph_total se existir; se não, cair para min_bid
        hourly = dph_total if math.isfinite(dph_total) and dph_total > 0 else min_bid

    if not math.isfinite(hourly) or hourly <= 0:
        return None

    month = hourly * HOURS_PER_MONTH
    return {
        "id": offer.get("id"),
        "gpu_name": offer.get("gpu_name"),
        "num_gpus": offer.get("num_gpus"),
        "total_flops": tflops,
        "hourly_assumed": hourly,
        "month_usd": month,
        "tflops_per_month_dollar": (tflops / month) if month > 0 else 0.0,
        "dph_total": offer.get("dph_total"),
        "min_bid": offer.get("min_bid"),
        "reliability": offer.get("reliability"),
        "verification": offer.get("verification"),
        "datacenter": offer.get("datacenter"),
        "geolocation": offer.get("geolocation"),
    }


# -------------------------
# SSH runner
# -------------------------
def ssh_run(host: str, port: int, key_path: str, cmd: str, timeout_s: int = 1800) -> Tuple[int, str]:
    """
    Executa comando via SSH usando o binário 'ssh' do sistema.
    """
    key_path = os.path.expanduser(key_path)

    ssh_cmd = [
        "ssh",
        "-i", key_path,
        "-p", str(port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=~/.ssh/known_hosts",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        f"root@{host}",
        cmd,
    ]

    try:
        p = subprocess.run(
            ssh_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        return p.returncode, p.stdout
    except FileNotFoundError:
        raise RuntimeError("Comando 'ssh' não encontrado. Instale OpenSSH client ou use --method api.")
    except subprocess.TimeoutExpired:
        return 124, f"[timeout] {cmd}"


# -------------------------
# Commands
# -------------------------
def cmd_rank(api: VastAPI, args: argparse.Namespace) -> None:
    # Search offers endpoint: POST /bundles/ com filtros estruturados
    body = {
        "limit": int(args.limit),
        "type": args.type,  # on-demand | bid | reserved
        "rentable": {"eq": True},
        "rented": {"eq": False},
        "disable_bundling": True,
    }
    if args.verified:
        body["verified"] = {"eq": True}
    if args.datacenter:
        body["datacenter"] = {"eq": True}
    if args.num_gpus:
        body["num_gpus"] = {"eq": int(args.num_gpus)}
    if args.min_vram:
        body["gpu_ram"] = {"gte": int(args.min_vram)}  # em MB

    offers = api.search_offers(body)

    rows: List[Dict[str, Any]] = []
    for o in offers:
        # filtro opcional por substring de gpu_name (já que o endpoint usa filtros estruturados)
        if args.gpu_contains:
            name = (o.get("gpu_name") or "")
            if args.gpu_contains.lower() not in name.lower():
                continue

        r = compute_value_row(o)
        if r:
            rows.append(r)

    rows.sort(key=lambda r: r["tflops_per_month_dollar"], reverse=True)

    print(f"Ofertas retornadas (após filtro): {len(rows)}")
    print("TOP (maior TFLOPs por $/mês):")
    for i, r in enumerate(rows[: args.top], 1):
        print(
            f"{i:>2}. offer_id={r['id']} | {r.get('num_gpus')}x {r.get('gpu_name')} | "
            f"TFLOPs={r['total_flops']:.1f} | ~${r['month_usd']:.0f}/mês | "
            f"TFLOPs/$mês={r['tflops_per_month_dollar']:.6f} | "
            f"rel={r.get('reliability','?')} | {r.get('geolocation','')}"
        )


def cmd_bid(api: VastAPI, args: argparse.Namespace) -> None:
    state = load_state(args.state)

    # criar instância bid (interruptible) via /asks/{id} com "price"
    body = {
        "image": args.image,
        "label": args.label,
        "runtype": "ssh",
        "target_state": "running",
        "price": float(args.price),  # bid $/h (interruptible)
        "disk": float(args.disk) if args.disk else None,
        "cancel_unavail": bool(args.cancel_unavail),
    }
    # remover Nones
    body = {k: v for k, v in body.items() if v is not None}

    instance_id = api.create_instance(int(args.offer_id), body)
    print(f"[OK] Criada instância (bid) instance_id={instance_id}")

    # attach ssh key (recomendado) — usa seu .pub
    if args.ssh_pubkey:
        pubkey = read_text_file(args.ssh_pubkey).strip()
        api.attach_ssh_key(instance_id, pubkey)
        print("[OK] SSH key anexada na instância.")
    else:
        print("[WARN] Você não passou --ssh-pubkey. Sem key, o SSH provavelmente vai falhar (Vast usa key-only).")

    # pegar detalhes e salvar estado
    inst = api.get_instance(instance_id)
    record = {
        "id": instance_id,
        "offer_id": int(args.offer_id),
        "bid_price": float(args.price),
        "label": args.label,
        "created_ts": time.time(),
        "actual_status": inst.get("actual_status"),
        "cur_state": inst.get("cur_state"),
        "intended_status": inst.get("intended_status"),
        "is_bid": inst.get("is_bid"),
        "ssh_host": inst.get("ssh_host"),
        "ssh_port": inst.get("ssh_port"),
        "geolocation": inst.get("geolocation"),
        "gpu_name": inst.get("gpu_name"),
        "num_gpus": inst.get("num_gpus"),
    }
    upsert_instance(state, record)
    save_state(args.state, state)
    print(f"[OK] Estado salvo em {args.state}")


def cmd_sync(api: VastAPI, args: argparse.Namespace) -> None:
    state = load_state(args.state)
    instances = api.list_instances()

    # atualizar/descobrir instâncias bid abertas
    found = 0
    for inst in instances:
        # "is_bid" aparece nos objetos da API de instâncias
        if args.only_bids and not bool(inst.get("is_bid")):
            continue

        record = {
            "id": int(inst["id"]),
            "actual_status": inst.get("actual_status"),
            "cur_state": inst.get("cur_state"),
            "intended_status": inst.get("intended_status"),
            "is_bid": inst.get("is_bid"),
            "ssh_host": inst.get("ssh_host"),
            "ssh_port": inst.get("ssh_port"),
            "public_ipaddr": inst.get("public_ipaddr"),
            "geolocation": inst.get("geolocation"),
            "gpu_name": inst.get("gpu_name"),
            "num_gpus": inst.get("num_gpus"),
            "dph_total": inst.get("dph_total"),
            "min_bid": inst.get("min_bid"),
            "total_flops": inst.get("total_flops"),
            "reliability": inst.get("reliability2", inst.get("reliability")),
            "verification": inst.get("verification"),
        }
        upsert_instance(state, record)
        found += 1

    save_state(args.state, state)
    print(f"[OK] Sync concluído. Atualizadas/descobertas: {found}. Arquivo: {args.state}")

    # imprimir resumo
    rows = list(state.get("instances", {}).values())
    rows.sort(key=lambda r: (r.get("is_bid") is not True, r.get("actual_status") != "running", -float(r.get("id", 0))))
    print("\nResumo (primeiras 30):")
    for r in rows[:30]:
        print(
            f"- id={r.get('id')} | is_bid={r.get('is_bid')} | status={r.get('actual_status')}/{r.get('cur_state')} | "
            f"{r.get('num_gpus')}x {r.get('gpu_name')} | ssh={r.get('ssh_host')}:{r.get('ssh_port')}"
        )


def cmd_run(api: VastAPI, args: argparse.Namespace) -> None:
    state = load_state(args.state)
    instances = list(state.get("instances", {}).values())

    # filtro
    targets = []
    for r in instances:
        if args.only_bids and not bool(r.get("is_bid")):
            continue
        if args.only_running and (r.get("actual_status") != "running" and r.get("cur_state") != "running"):
            continue
        targets.append(r)

    if not targets:
        print("Nada para rodar (verifique se já fez sync e/ou se há bids running).")
        return

    print(f"Rodando comando em {len(targets)} instância(s): method={args.method}")
    for r in targets:
        iid = int(r["id"])
        print(f"\n== instance_id={iid} ({r.get('gpu_name')}, status={r.get('actual_status')}) ==")

        if args.method == "api":
            # Vast execute endpoint
            out = api.execute(iid, args.cmd)
            print(json.dumps(out, indent=2))
            continue

        # SSH
        host = r.get("ssh_host") or r.get("public_ipaddr")
        port = r.get("ssh_port")
        if not host or not port:
            print("[SKIP] Sem ssh_host/ssh_port no estado. Rode 'sync' ou use --method api.")
            continue

        rc, out = ssh_run(host=str(host), port=int(port), key_path=args.ssh_key, cmd=args.cmd)
        print(out.rstrip())
        if rc != 0:
            print(f"[WARN] rc={rc}")


def read_text_file(path: str) -> str:
    with open(os.path.expanduser(path), "r", encoding="utf-8") as f:
        return f.read()


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Vast.ai bid manager (criar bid, salvar/atualizar, SSH commands)")
    p.add_argument("--state", default=DEFAULT_STATE_PATH, help="Arquivo JSON de estado (default: vast_bids.json)")
    p.add_argument("--api-key", default=os.getenv("VAST_API_KEY"), help="API key (ou use env VAST_API_KEY)")

    sub = p.add_subparsers(dest="cmd", required=True)

    # rank
    pr = sub.add_parser("rank", help="Ranking $/mês vs TFLOPs usando search offers")
    pr.add_argument("--type", default="bid", choices=["bid", "on-demand", "reserved"], help="Tipo de offer")
    pr.add_argument("--limit", type=int, default=2000)
    pr.add_argument("--top", type=int, default=25)
    pr.add_argument("--verified", action="store_true")
    pr.add_argument("--datacenter", action="store_true")
    pr.add_argument("--num-gpus", type=int, default=1)
    pr.add_argument("--min-vram", type=int, default=0, help="VRAM mínima em MB (ex: 24000)")
    pr.add_argument("--gpu-contains", default="", help="Filtro substring em gpu_name (ex: 3090, 4090, 5090)")
    pr.set_defaults(func=cmd_rank)

    # bid create
    pb = sub.add_parser("bid", help="Criar instância interruptível (bid) a partir de offer_id")
    pb.add_argument("offer_id", type=int, help="offer_id (ask_id) da Vast")
    pb.add_argument("--price", type=float, required=True, help="Lance ($/h) para interruptible (campo 'price')")
    pb.add_argument("--image", default="vastai/base-image:@vastai-automatic-tag")
    pb.add_argument("--label", default="bid-job")
    pb.add_argument("--disk", type=float, default=0.0, help="Disco em GB (0 = padrão)")
    pb.add_argument("--cancel-unavail", action="store_true", help="Cancelar se não iniciar imediatamente")
    pb.add_argument("--ssh-pubkey", default=os.getenv("VAST_SSH_PUBKEY_PATH"), help="Caminho do .pub para anexar na instância")
    pb.set_defaults(func=cmd_bid)

    # sync
    ps = sub.add_parser("sync", help="Atualiza vast_bids.json com as instâncias atuais (e descobre bids abertas)")
    ps.add_argument("--only-bids", action="store_true", help="Salvar/atualizar apenas instâncias is_bid=True")
    ps.set_defaults(func=cmd_sync)

    # run commands
    pc = sub.add_parser("run", help="Roda comando nas instâncias do arquivo (SSH ou API execute)")
    pc.add_argument("--cmd", required=True, help='Comando a rodar, ex: "nvidia-smi"')
    pc.add_argument("--method", default="ssh", choices=["ssh", "api"])
    pc.add_argument("--only-bids", action="store_true", default=True, help="(default) só bids")
    pc.add_argument("--only-running", action="store_true", default=True, help="(default) só running")
    pc.add_argument("--ssh-key", default=os.getenv("VAST_SSH_KEY_PATH", "~/.ssh/id_ed25519"), help="Chave privada para SSH")
    pc.set_defaults(func=cmd_run)

    return p


def main() -> None:
    args = build_argparser().parse_args()
    api = VastAPI(api_key=args.api_key)
    args.func(api, args)


if __name__ == "__main__":
    main()
\