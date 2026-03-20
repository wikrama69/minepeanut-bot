#!/usr/bin/env python3
“””
MinePeanut ($PEANUT) Mining Bot
Railway-ready | ED25519 signing | PoW solver | Auto wallet retry

Install: pip install requests cryptography colorama
Usage:   python minepeanut_bot.py –agent-id peanut_braddo –wallet 0xAlamat
Railway: set env vars AGENT_ID, ETH_WALLET, PEANUT_PRIVATE_KEY
“””

import argparse, base64, hashlib, json, os, sys, time, uuid
from datetime import datetime

import requests
from colorama import Fore, Style, init
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
Encoding, NoEncryption, PublicFormat, PrivateFormat,
)

# ── CONFIG ────────────────────────────────────────────────

BASE_URL         = “https://wrcenmardnbprfpqhrqe.supabase.co/functions/v1/peanut-mining”
KEYS_FILE        = “peanut_keys.json”
TASK_INTERVAL    = 3    # detik antar task
REGISTER_TIMEOUT = 60   # timeout register (sering overload)
WALLET_TIMEOUT   = 60   # timeout update-wallet
API_TIMEOUT      = 30   # timeout endpoint lain

init(autoreset=True)

def log(level, msg):
ts = datetime.now().strftime(”%H:%M:%S”)
c = {“INFO”: Fore.CYAN, “SUCCESS”: Fore.GREEN, “WARN”: Fore.YELLOW,
“ERROR”: Fore.RED, “MINING”: Fore.MAGENTA, “REWARD”: Fore.YELLOW + Style.BRIGHT}
print(f”{Fore.WHITE}[{ts}] {c.get(level, Fore.WHITE)}[{level}]{Style.RESET_ALL} {msg}”, flush=True)

# ── KEYPAIR ───────────────────────────────────────────────

def load_or_generate_keys(agent_id):
env_key = os.environ.get(“PEANUT_PRIVATE_KEY”, “”).strip()
if env_key:
try:
priv  = Ed25519PrivateKey.from_private_bytes(base64.b64decode(env_key))
pub   = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
log(“INFO”, “Keypair loaded from env var PEANUT_PRIVATE_KEY”)
return priv, pub.hex(), base64.b64encode(pub).decode()
except Exception as e:
log(“WARN”, f”PEANUT_PRIVATE_KEY invalid: {e}”)

```
if os.path.exists(KEYS_FILE):
    d = json.load(open(KEYS_FILE))
    if d.get("agent_id") == agent_id:
        priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(d["private_key_b64"]))
        log("INFO", f"Keypair loaded from {KEYS_FILE}")
        return priv, d["public_key_hex"], d["public_key_b64"]

priv      = Ed25519PrivateKey.generate()
pub       = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
priv_raw  = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
pub_hex   = pub.hex()
pub_b64   = base64.b64encode(pub).decode()
priv_b64  = base64.b64encode(priv_raw).decode()

try:
    json.dump({"agent_id": agent_id, "public_key_hex": pub_hex,
               "public_key_b64": pub_b64, "private_key_b64": priv_b64},
              open(KEYS_FILE, "w"), indent=2)
except Exception:
    pass

log("SUCCESS", "Generated new ED25519 keypair!")
log("WARN",    "Simpan env var ini di Railway supaya keypair tidak reset:")
log("WARN",    f"  PEANUT_PRIVATE_KEY = {priv_b64}")
return priv, pub_hex, pub_b64
```

# ── SIGNING ───────────────────────────────────────────────

def sign(priv, data):
msg = json.dumps(data, sort_keys=True, separators=(”,”, “:”)).encode()
return priv.sign(msg).hex()

# ── SOLVERS ───────────────────────────────────────────────

def solve_hash(payload_b64, difficulty):
try:    pb = base64.b64decode(payload_b64 + “==”)
except: pb = payload_b64.encode()
prefix = “0” * difficulty
nonce, start = 0, time.time()
log(“MINING”, f”Solving PoW difficulty={difficulty}…”)
while True:
d = hashlib.sha256(pb + nonce.to_bytes(8, “little”)).hexdigest()
if d.startswith(prefix):
ms = int((time.time() - start) * 1000)
log(“SUCCESS”, f”Solved nonce={nonce} ({ms}ms)”)
return d, ms
nonce += 1
if nonce > 10_000_000:
return d, int((time.time() - start) * 1000)

def solve_matrix(payload_b64):
start = time.time()
try:
d = json.loads(base64.b64decode(payload_b64 + “==”))
a, b = d[“a”], d[“b”]
res  = [[sum(a[i][k]*b[k][j] for k in range(len(a[0])))
for j in range(len(b[0]))] for i in range(len(a))]
sol  = hashlib.sha256(json.dumps(res).encode()).hexdigest()
except:
sol  = hashlib.sha256(payload_b64.encode()).hexdigest()
return sol, int((time.time() - start) * 1000)

# ── API ───────────────────────────────────────────────────

def api(method, path, timeout=API_TIMEOUT, retries=5, **kwargs):
url = f”{BASE_URL}{path}”
for i in range(1, retries + 1):
try:
r = requests.request(method, url, timeout=timeout, **kwargs)
if r.status_code == 200:
return r.json()
log(“WARN”, f”HTTP {r.status_code} {path} (try {i}/{retries}): {r.text[:80]}”)
except Exception as e:
log(“WARN”, f”Timeout {path} (try {i}/{retries}): {e}”)
if i < retries:
wait = min(10 * (2 ** (i-1)), 120)
log(“INFO”, f”Retry in {wait}s…”)
time.sleep(wait)
return None

# ── REGISTER ──────────────────────────────────────────────

def register(agent_id, pub_b64):
log(“INFO”, f”Registering: {Fore.CYAN}{agent_id}”)
for i in range(1, 6):
try:
r = requests.post(f”{BASE_URL}/register”, timeout=REGISTER_TIMEOUT, json={
“agent_id”: agent_id, “public_key”: pub_b64,
“compute_capability”: “GPU”, “max_vcus”: 1000,
})
if r.status_code == 200:
log(“SUCCESS”, f”Registered! epoch={r.json().get(‘epoch_start’,’?’)}”)
return True
if r.status_code == 409:
log(“INFO”, “Sudah terdaftar sebelumnya ✓”)
return True
log(“WARN”, f”Register HTTP {r.status_code} (attempt {i}/5): {r.text[:80]}”)
except Exception as e:
log(“WARN”, f”Register timeout (attempt {i}/5): {e}”)
wait = 20 * i
log(“INFO”, f”Retry register in {wait}s…”)
time.sleep(wait)
log(“WARN”, “Register gagal 5x — skip, langsung mining…”)
return False

# ── UPDATE WALLET ─────────────────────────────────────────

def update_wallet(agent_id, pub_b64, wallet, max_retries=10):
if not wallet or not wallet.startswith(“0x”):
log(“WARN”, “Wallet tidak valid, skip update wallet”)
return False
log(“INFO”, f”Setting wallet: {Fore.CYAN}{wallet[:10]}…{wallet[-6:]}”)
for i in range(1, max_retries + 1):
try:
r = requests.post(f”{BASE_URL}/update-wallet”, timeout=WALLET_TIMEOUT, json={
“agent_id”:       agent_id,
“public_key”:     pub_b64,
“wallet_address”: wallet,
})
if r.status_code == 200 and r.json().get(“status”) == “updated”:
log(“SUCCESS”, f”Wallet berhasil di-set! ✓”)
return True
log(“WARN”, f”Wallet HTTP {r.status_code} (attempt {i}/{max_retries}): {r.text[:80]}”)
except Exception as e:
log(“WARN”, f”Wallet timeout (attempt {i}/{max_retries}): {e}”)
wait = min(15 * i, 120)
log(“INFO”, f”Retry wallet in {wait}s…”)
time.sleep(wait)
log(“ERROR”, “Wallet gagal di-set setelah semua retry!”)
return False

# ── STATS ─────────────────────────────────────────────────

class Stats:
def **init**(self):
self.vcus = self.peanut = self.solved = self.failed = 0
self.start = time.time()

```
def ok(self, v, p): self.vcus += v; self.peanut += p; self.solved += 1
def fail(self):     self.failed += 1

def show(self):
    e = int(time.time() - self.start)
    h, r = divmod(e, 3600); m, s = divmod(r, 60)
    print(f"\n{Fore.YELLOW}{'═'*48}", flush=True)
    print(f"  Uptime  : {h:02d}:{m:02d}:{s:02d}")
    print(f"  Solved  : {Fore.GREEN}{self.solved}  {Fore.RED}Failed: {self.failed}")
    print(f"  VCUs    : {Fore.CYAN}{self.vcus:,}")
    print(f"  $PEANUT : {Fore.YELLOW}{self.peanut:,}")
    print(f"{Fore.YELLOW}{'═'*48}\n", flush=True)
```

# ── MINING LOOP ───────────────────────────────────────────

def mine(agent_id, priv, pub_b64, wallet=””):
stats     = Stats()
last_task = None
counter   = 0

```
print(f"\n{Fore.MAGENTA}{'═'*48}", flush=True)
print(f"{Fore.MAGENTA}  🥜 MinePeanut Bot — Mining Started")
print(f"{Fore.MAGENTA}  Agent : {agent_id}")
print(f"{Fore.MAGENTA}  Wallet: {wallet[:10]}...{wallet[-6:] if wallet else 'NOT SET'}")
print(f"{Fore.MAGENTA}{'═'*48}\n", flush=True)

while True:
    try:
        task = api("GET", "/tasks/current")
        if not task:
            log("WARN", f"No task, retry in {TASK_INTERVAL}s...")
            time.sleep(TASK_INTERVAL)
            continue

        tid  = task.get("task_id", "")
        typ  = task.get("type", "hash_challenge")
        diff = task.get("difficulty", 3)
        pay  = task.get("payload", "")
        ep   = task.get("epoch", "?")

        if tid == last_task:
            time.sleep(TASK_INTERVAL)
            continue

        log("INFO", f"Task {Fore.CYAN}{tid}{Style.RESET_ALL} epoch={ep} type={typ} diff={diff}")

        sol, ms = solve_matrix(pay) if typ == "matrix_multiplication" \
                  else solve_hash(pay, diff)

        sig = sign(priv, {"agent_id": agent_id, "task_id": tid, "solution": sol})

        res = api("POST", "/submit", retries=3, json={
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
        counter  += 1

        if counter % 10 == 0:
            stats.show()

        # Re-set wallet setiap 50 task, jaga-jaga kalau wallet_address null di server
        if counter % 50 == 0 and wallet:
            log("INFO", "Periodic wallet re-check & update...")
            update_wallet(agent_id, pub_b64, wallet, max_retries=3)

        time.sleep(TASK_INTERVAL)

    except KeyboardInterrupt:
        log("INFO", "Stopped.")
        stats.show()
        sys.exit(0)
    except Exception as e:
        log("ERROR", f"Unexpected: {e}")
        time.sleep(10)
```

# ── MAIN ──────────────────────────────────────────────────

def main():
default_agent  = os.environ.get(“AGENT_ID”,   f”peanut_{uuid.uuid4().hex[:8]}”)
default_wallet = os.environ.get(“ETH_WALLET”, “”)

```
parser = argparse.ArgumentParser(description="MinePeanut Bot")
parser.add_argument("--agent-id", default=default_agent)
parser.add_argument("--wallet",   default=default_wallet)
parser.add_argument("--check",    action="store_true", help="Cek status lalu exit")
args = parser.parse_args()

priv, pub_hex, pub_b64 = load_or_generate_keys(args.agent_id)

if args.check:
    s = api("GET", "/network/status")
    if s: print(json.dumps(s, indent=2))
    a = api("GET", f"/allocations/{args.agent_id}")
    if a: print(json.dumps(a, indent=2))
    sys.exit(0)

# Register (skip kalau gagal)
register(args.agent_id, pub_b64)

# Set wallet — retry agresif sampai berhasil
if args.wallet and args.wallet.startswith("0x"):
    update_wallet(args.agent_id, pub_b64, args.wallet, max_retries=20)
else:
    log("WARN", "⚠  ETH_WALLET belum diset! Airdrop tidak akan diterima.")

mine(args.agent_id, priv, pub_b64, args.wallet)
```

if **name** == “**main**”:
main()
