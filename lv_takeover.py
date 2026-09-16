#!/usr/bin/env python3
"""
LightVela Takeover
==================

Take full control of LightVela sandbox instances over their debug/exec API:

  1. Verify sudo access through the instance exec endpoint
  2. Generate a fresh SSH keypair per run (or reuse an existing one)
  3. Inject the public key into the instance's authorized_keys
  4. Start sshd
  5. Harden SSH (password auth off, root login off, UFW tailscale-only)
  6. Install Tailscale and join your tailnet via a reusable auth key
  7. Verify end-to-end SSH connectivity over the tailnet IP

No credentials are ever stored in this repository. All secrets are read from
local files that must be git-ignored:

  tokens.txt      one LightVela bearer token per line (chmod 600 recommended)
  tailscale.key   one Tailscale reusable auth key (single line)
  SSH keypair     path supplied via --key; if missing, auto-generated

Usage
-----
  python lv_takeover.py                          # process every token in tokens.txt
  python lv_takeover.py --only prod,worker1      # filter by instance name
  python lv_takeover.py --key ~/.ssh/id_ed25519  # reuse an existing keypair
  python lv_takeover.py --token-file t.txt --ts-file ts.key --user root

Exit codes: 0 = all targeted instances taken over; 1 = at least one failure.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

API_BASE = "https://api.lightvela.ai/v1"
DEFAULT_TOKEN_FILE = "tokens.txt"
DEFAULT_TS_FILE = "tailscale.key"
DEFAULT_SSH_KEY = Path.home() / ".ssh" / "id_ed25519"
DEFAULT_USER = "agentuser"

# ────────────────────────────────────────────────────────────────────
# SSH key generation
# ────────────────────────────────────────────────────────────────────

def generate_keypair(priv_path: Path) -> None:
    """Generate an ed25519 keypair (no passphrase) at priv_path if absent."""
    if priv_path.exists():
        return
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(priv_path),
         "-C", "lightvela-takeover", "-q"],
        check=True,
    )
    print(f"[key] generated new keypair: {priv_path}")


def load_public_key(priv_path: Path) -> str:
    pub_path = priv_path.with_suffix(priv_path.suffix + ".pub")
    if not pub_path.exists():
        # some users pass the .pub path directly
        if priv_path.suffix == ".pub":
            return priv_path.read_text().strip()
        sys.exit(f"error: public key not found next to {priv_path}")
    return pub_path.read_text().strip()


# ────────────────────────────────────────────────────────────────────
# LightVela API helpers
# ────────────────────────────────────────────────────────────────────

def curl_json(url: str, token: str, body: dict | None = None,
              timeout: int = 30) -> dict:
    cmd = ["curl", "-s", "-m", str(timeout), url,
           "-H", f"authorization: Bearer {token}",
           "-H", f"cookie: lc_session={token}"]
    if body is not None:
        cmd += ["-X", "POST", "-H", "Content-Type: application/json",
                "-d", json.dumps(body)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"_raw": (r.stdout or r.stderr)[:200]}


def list_instances(token: str) -> list[dict]:
    d = curl_json(f"{API_BASE}/instances", token)
    return (d.get("data") or {}).get("items") or []


def exec_cmd(token: str, instance_id: str, command: str,
             timeout: int = 120) -> tuple[str, bool]:
    d = curl_json(f"{API_BASE}/instances/{instance_id}/debug/exec", token,
                  body={"command": command, "run_as_user": DEFAULT_USER},
                  timeout=timeout)
    data = d.get("data") or {}
    return data.get("output", ""), data.get("status") == "SUCCESS"


# ────────────────────────────────────────────────────────────────────
# Take-over pipeline
# ────────────────────────────────────────────────────────────────────

HARDENING_CONF = """\
PasswordAuthentication no
PermitRootLogin no
KbdInteractiveAuthentication no
MaxAuthTries 3
"""


def takeover(token: str, inst: dict, pubkey: str, authkey: str,
             hostname: str) -> tuple[str | None, str | None]:
    """Run the full take-over pipeline. Returns (tailnet_ip, error)."""
    iid = inst["instance_id"]
    name = inst.get("name") or iid[:8]

    # 1 ── sudo sanity check
    out, _ = exec_cmd(token, iid, "sudo -n true 2>/dev/null && echo SUDO_OK || echo SUDO_FAIL")
    if "SUDO_OK" not in out:
        return None, f"no sudo access ({out[:60]})"

    # 2+3 ── inject pubkey, start sshd
    setup = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f"grep -qF '{pubkey}' ~/.ssh/authorized_keys 2>/dev/null "
        f"|| echo '{pubkey}' >> ~/.ssh/authorized_keys; "
        "chmod 600 ~/.ssh/authorized_keys; "
        "sudo mkdir -p /run/sshd; "
        "pgrep -x sshd >/dev/null || sudo /usr/sbin/sshd; "
        "echo SSHD_DONE"
    )
    out, _ = exec_cmd(token, iid, setup)
    if "SSHD_DONE" not in out:
        return None, "ssh key/sshd setup failed"

    # 4 ── harden sshd + firewall (idempotent)
    harden = (
        f"printf '%s\\n' {json.dumps(HARDENING_CONF)} "
        "| sudo tee /etc/ssh/sshd_config.d/99-takeover-hardening.conf >/dev/null; "
        # cloud-init images ship PasswordAuthentication yes in these files — override
        "sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/;"
        "s/^PermitRootLogin .*/PermitRootLogin no/' "
        "/etc/ssh/sshd_config /etc/ssh/sshd_config.d/50-cloud-init.conf 2>/dev/null; "
        "sudo passwd -l " + DEFAULT_USER + " >/dev/null 2>&1; "
        "sudo ufw default deny incoming >/dev/null 2>&1; "
        "sudo ufw default allow outgoing >/dev/null 2>&1; "
        "sudo ufw allow in on tailscale0 >/dev/null 2>&1; "
        "sudo ufw --force enable >/dev/null 2>&1; "
        "sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd; "
        "echo HARDENED"
    )
    out, _ = exec_cmd(token, iid, harden)
    if "HARDENED" not in out:
        return None, "ssh hardening failed"

    # 5 ── install tailscale if missing
    out, _ = exec_cmd(token, iid,
        "command -v tailscale >/dev/null 2>&1 || "
        "curl -fsSL https://tailscale.com/install.sh | sh >/dev/null 2>&1; "
        "echo TS_READY")
    if "TS_READY" not in out:
        return None, "tailscale install failed"

    # 6 ── join tailnet (reusable authkey, no manual approval)
    # --ssh=false: Tailscale SSH would add a credential-less "none" auth path
    out, _ = exec_cmd(token, iid,
        f"sudo tailscale up --ssh=false --authkey={authkey} "
        f"--hostname={hostname} --reset >/dev/null 2>&1; "
        "tailscale ip -4 | head -1", timeout=90)
    ts_ip = out.strip().splitlines()[-1].strip() if out.strip() else ""
    if not ts_ip.startswith("100."):
        return None, f"tailscale join failed ({out[:80]})"

    return ts_ip, None


def ssh_check(ts_ip: str, key: Path, user: str = DEFAULT_USER) -> bool:
    r = subprocess.run(
        ["ssh", "-i", str(key), "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
         f"{user}@{ts_ip}", "echo SSH_OK_$(hostname)"],
        capture_output=True, text=True, timeout=20)
    return "SSH_OK_" in r.stdout


# ────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Take over LightVela sandbox instances via debug/exec.")
    ap.add_argument("--token-file", default=DEFAULT_TOKEN_FILE,
                    help="file with one bearer token per line (default: tokens.txt)")
    ap.add_argument("--ts-file", default=DEFAULT_TS_FILE,
                    help="file containing the Tailscale authkey (default: tailscale.key)")
    ap.add_argument("--key", default=str(DEFAULT_SSH_KEY),
                    help="SSH private key path; auto-generated if missing")
    ap.add_argument("--only", help="comma-separated instance names to process")
    ap.add_argument("--user", default=DEFAULT_USER,
                    help=f"SSH user (default: {DEFAULT_USER})")
    args = ap.parse_args()

    key_path = Path(args.key).expanduser()
    generate_keypair(key_path)
    pubkey = load_public_key(key_path)

    ts_file = Path(args.ts_file)
    if not ts_file.exists():
        sys.exit(f"error: tailscale authkey file not found: {ts_file}")
    authkey = ts_file.read_text().strip().splitlines()[0].strip()

    tok_file = Path(args.token_file)
    if not tok_file.exists():
        sys.exit(f"error: token file not found: {tok_file}")
    tokens = [t.strip() for t in tok_file.read_text().splitlines()
              if t.strip() and not t.startswith("#")]
    if not tokens:
        sys.exit("error: no tokens found in token file")

    only = {x.strip() for x in args.only.split(",")} if args.only else None
    failures = 0
    results: list[tuple[str, str, str]] = []

    for tok in tokens:
        for inst in list_instances(tok):
            name = inst.get("name") or inst["instance_id"][:8]
            if only and name not in only:
                continue
            if inst.get("status") != "Running":
                print(f"[{name}] status={inst.get('status')} — skipped")
                continue

            print(f"[{name}] taking over {inst['instance_id']} ...")
            ts_ip, err = takeover(tok, inst, pubkey, authkey, f"lvp-{name}")
            if err:
                print(f"[{name}] ✗ {err}")
                results.append((name, "-", err))
                failures += 1
                continue

            ok = ssh_check(ts_ip, key_path, args.user)
            print(f"[{name}] ✓ tailnet {ts_ip} — ssh {'OK' if ok else 'FAILED'}")
            results.append((name, ts_ip, "ok" if ok else "ssh-fail"))
            if not ok:
                failures += 1

    print("\n═══ SUMMARY ═══")
    for name, ip, st in results:
        print(f"{name:<14} {ip:<18} {st}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
