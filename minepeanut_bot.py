#!/usr/bin/env python3
"""
MinePeanut ($PEANUT) Mining Bot
================================
Auto-mining bot with real ED25519 signing & PoW solver.
Railway-ready: keypair disimpan via env var PEANUT_PRIVATE_KEY

Install dependencies:
    pip install requests cryptography colorama

Usage (local):
    python minepeanut_bot.py --agent-id my_bot_001 --wallet 0xYourEthAddress

Usage (Railway):
    Set env vars: AGENT_ID, ETH_WALLET, PEANUT_PRIVATE_KEY
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime

import requests
from colorama import Fore, Style, init
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PublicFormat, PrivateFormat,
)

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
BASE_URL      = "https://wrcenmardnbprfpqhrqe.supabase.co/functions/v1/peanut-mining"
KEYS_FILE     = "peanut_keys.json"
RETRY_DELAY    = 10   # detik base delay
TASK_INTERVAL  = 3    # detik antar task
MAX_RETRIES    = 10   # retry lebih banyak
REGISTER_TIMEOUT = 60 # timeout khusus register (server sering overload)

init(autoreset=True)

def log(level: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO":    Fore.CYAN,
        "SUCCESS": Fore.GREEN,
        "WARN":    Fore.YELLOW,
        "ERROR":   Fore.RED,
        "MINING":  Fore.MAGENTA,
        "REWARD":  Fore.YELLOW + Style.BRIGHT,
    }
    color = colors.get(level, Fore.WHITE)
    print(f"{Fore.WHITE}[{ts}] {color}[{level}]{Style.RESET_ALL} {msg}", flush=True)


# ─────────────────────────────────────────────
#  KEYPAIR MANAGEMENT
#  Railway tidak punya persistent disk →
#  simpan PEANUT_PRIVATE_KEY di env var Railway
# ─────────────────────────────────────────────
def load_or_generate_keys(agent_id: str):
    env_key = os.environ.get("PEANUT_PRIVATE_KEY", "").strip()

    if env_key:
        try:
            priv_bytes  = base64.b64decode(env_key)
            private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
            pub_bytes   = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            log("INFO", "Loaded keypair from env var PEANUT_PRIVATE_KEY")
            return private_key, pub_bytes.hex(), base64.b64encode(pub_bytes).decode()
        except Exception as e:
            log("WARN", f"PEANUT_PRIVATE_KEY invalid ({e}), generating new...")

    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE) as f:
            data = json.load(f)
        if data.get("agent_id") == agent_id:
            priv_bytes  = base64.b64decode(data["private_key_b64"])
            private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
            log("INFO", f"Loaded keypair from {KEYS_FILE}")
            return private_key, data["public_key_hex"], data["public_key_b64"]

    # Generate baru
    private_key = Ed25519PrivateKey.generate()
    pub_bytes   = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_bytes  = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_hex     = pub_bytes.hex()
    pub_b64     = base64.b64encode(pub_bytes).decode()
    priv_b64    = base64.b64encode(priv_bytes).decode()

    try:
        with open(KEYS_FILE, "w") as f:
            json.dump({"agent_id": agent_id, "public_key_hex": pub_hex,
                       "public_key_b64": pub_b64, "private_key_b64": priv_b64}, f, indent=2)
    except Exception:
        pass

    log("SUCCESS", "Generated new ED25519 keypair!")
    log("WARN",    "⚠  Agar keypair tidak reset tiap deploy Railway, tambahkan env var:")
    log("WARN",    f"   PEANUT_PRIVATE_KEY = {priv_b64}")
    return private_key, pub_hex, pub_b64


# ─────────────────────────────────────────────
#  SIGNING
# ─────────────────────────────────────────────
def sign_payload(private_key: Ed25519PrivateKey, data: dict) -> str:
    msg = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return private_key.sign(msg).hex()


# ─────────────────────────────────────────────
#  SOLVERS
# ─────────────────────────────────────────────
def solve_hash_challenge(payload_b64: str, difficulty: int):
    try:
        payload_bytes = base64.b64decode(payload_b64 + "==")
    except Exception:
        payload_bytes = payload_b64.encode()

    prefix = "0" * difficulty
    nonce  = 0
    start  = time.time()
    log("MINING", f"Solving PoW difficulty={difficulty}...")

    while True:
        digest = hashlib.sha256(payload_bytes + nonce.to_bytes(8, "little")).hexdigest()
        if digest.startswith(prefix):
            ms = int((time.time() - start) * 1000)
            log("SUCCESS", f"Solved nonce={nonce} hash={digest[:16]}... ({ms}ms)")
            return digest, ms
        nonce += 1
        if nonce > 10_000_000:
            ms = int((time.time() - start) * 1000)
            log("WARN", "Max nonce, submitting best effort")
            return digest, ms


def solve_matrix(payload_b64: str):
    start = time.time()
    try:
        d      = json.loads(base64.b64decode(payload_b64 + "=="))
        a, b   = d["a"], d["b"]
        cols_a = len(a[0])
        result = [[sum(a[i][k] * b[k][j] for k in range(cols_a))
                   for j in range(len(b[0]))] for i in range(len(a))]
        sol = hashlib.sha256(json.dumps(result).encode()).hexdigest()
    except Exception:
        sol = hashlib.sha256(payload_b64.encode()).hexdigest()
    return sol, int((time.time() - start) * 1000)


# ─────────────────────────────────────────────
#  API
# ─────────────────────────────────────────────
def api(method, path, timeout=30, **kwargs):
    url = f"{BASE_URL}{path}"
    for i in range(1, MAX_RETRIES + 1):
        try:
            r = requests.request(method, url, timeout=timeout, **kwargs)
            if r.status_code == 200:
                return r.json()
            log("WARN", f"HTTP {r.status_code} {path} (try {i}): {r.text[:100]}")
        except Exception as e:
            log("ERROR", f"Request error (try {i}): {e}")
        if i < MAX_RETRIES:
            wait = min(RETRY_DELAY * (2 ** (i - 1)), 120)
            log("INFO", f"Retry in {wait}s...")
            time.sleep(wait)
    return None


def register_agent(agent_id, pub_b64):
    log("INFO", f"Registering: {Fore.CYAN}{agent_id}")
    r = api("POST", "/register", timeout=REGISTER_TIMEOUT, json={
        "agent_id": agent_id, "public_key": pub_b64,
        "compute_capability": "GPU", "max_vcus": 1000,
    })
    if r:
        log("SUCCESS", f"Registered! epoch_start={r.get('epoch_start','?')}")
        return True
    log("ERROR", "Registration failed")
    return False


def update_wallet(agent_id, pub_b64, wallet):
    log("INFO", f"Setting wallet: {Fore.CYAN}{wallet}")
    r = api("POST", "/update-wallet", json={
        "agent_id": agent_id, "public_key": pub_b64, "wallet_address": wallet,
    })
    if r and r.get("status") == "updated":
        log("SUCCESS", "Wallet set!")
        return True
    log("WARN", f"Wallet response: {r}")
    return False


# ─────────────────────────────────────────────
#  STATS
# ─────────────────────────────────────────────
class Stats:
    def __init__(self):
        self.vcus = self.peanut = self.solved = self.failed = 0
        self.start = time.time()

    def ok(self, v, p):
        self.vcus += v; self.peanut += p; self.solved += 1

    def fail(self): self.failed += 1

    def show(self):
        e    = int(time.time() - self.start)
        h, r = divmod(e, 3600); m, s = divmod(r, 60)
        print(f"\n{Fore.YELLOW}{'═'*48}", flush=True)
        print(f"  Uptime  : {h:02d}:{m:02d}:{s:02d}")
        print(f"  Solved  : {Fore.GREEN}{self.solved}  {Fore.RED}Failed: {self.failed}")
        print(f"  VCUs    : {Fore.CYAN}{self.vcus:,}")
        print(f"  $PEANUT : {Fore.YELLOW}{self.peanut:,}")
        print(f"{Fore.YELLOW}{'═'*48}\n", flush=True)


# ─────────────────────────────────────────────
#  MINING LOOP
# ─────────────────────────────────────────────
def mine(agent_id, private_key, pub_b64):
    stats     = Stats()
    last_task = None
    n         = 0

    print(f"\n{Fore.MAGENTA}{'═'*48}", flush=True)
    print(f"{Fore.MAGENTA}  🥜 MinePeanut Bot — Started")
    print(f"{Fore.MAGENTA}  Agent: {agent_id}")
    print(f"{Fore.MAGENTA}{'═'*48}\n", flush=True)

    while True:
        try:
            task = api("GET", "/tasks/current")
            if not task:
                time.sleep(RETRY_DELAY); continue

            tid  = task.get("task_id", "")
            typ  = task.get("type", "hash_challenge")
            diff = task.get("difficulty", 3)
            pay  = task.get("payload", "")
            ep   = task.get("epoch", "?")

            if tid == last_task:
                time.sleep(TASK_INTERVAL); continue

            log("INFO", f"Task {Fore.CYAN}{tid}{Style.RESET_ALL} epoch={ep} type={typ} diff={diff}")

            sol, ms = solve_matrix(pay) if typ == "matrix_multiplication" \
                      else solve_hash_challenge(pay, diff)

            sig = sign_payload(private_key, {"agent_id": agent_id, "task_id": tid, "solution": sol})

            res = api("POST", "/submit", json={
                "agent_id": agent_id, "task_id": tid,
                "solution": sol, "signature": sig, "compute_time_ms": ms,
            })

            if res:
                status = res.get("status", "?")
                v, p   = res.get("vcus_credited", 0), res.get("peanut_earned", 0)
                if status == "verified":
                    stats.ok(v, p)
                    log("REWARD", f"✓ +{v} VCUs | +{p:,} $PEANUT | Total: {stats.peanut:,}")
                else:
                    stats.fail()
                    log("WARN", f"✗ {res.get('error', status)}")
            else:
                stats.fail()

            last_task = tid
            n += 1
            if n % 10 == 0:
                stats.show()

            time.sleep(TASK_INTERVAL)

        except KeyboardInterrupt:
            log("INFO", "Stopped by user.")
            stats.show()
            sys.exit(0)
        except Exception as e:
            log("ERROR", f"{e}")
            time.sleep(RETRY_DELAY)


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    default_agent  = os.environ.get("AGENT_ID",   f"peanut_{uuid.uuid4().hex[:8]}")
    default_wallet = os.environ.get("ETH_WALLET", "")

    parser = argparse.ArgumentParser(description="MinePeanut Bot")
    parser.add_argument("--agent-id", default=default_agent)
    parser.add_argument("--wallet",   default=default_wallet)
    parser.add_argument("--check",    action="store_true", help="Cek status & exit")
    args = parser.parse_args()

    private_key, pub_hex, pub_b64 = load_or_generate_keys(args.agent_id)

    if args.check:
        s = api("GET", "/network/status")
        if s: print(json.dumps(s, indent=2))
        a = api("GET", f"/allocations/{args.agent_id}")
        if a: print(json.dumps(a, indent=2))
        sys.exit(0)

    register_agent(args.agent_id, pub_b64)

    if args.wallet and args.wallet.startswith("0x"):
        update_wallet(args.agent_id, pub_b64, args.wallet)
    else:
        log("WARN", "⚠  Set ETH_WALLET env var untuk receive airdrop!")

    mine(args.agent_id, private_key, pub_b64)


if __name__ == "__main__":
    main()
