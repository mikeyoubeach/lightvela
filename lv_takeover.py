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
  python lv_takeover.py --api https://api.lightvela.com/v1
  python lv_takeover.py --dry-run                # read-only: report what it sees

API base
--------
The CN console (lightvela.com) and the intl console (lightvela.ai) are separate
deployments with separate API hosts. A token from one is rejected with HTTP 401
by the other, which looks exactly like an expired token. Set the right one once:

  --api https://api.lightvela.com/v1           (CN)
  --api https://api.lightvela.ai/v1            (intl, default)
  LIGHTVELA_API=https://api.lightvela.com/v1   (environment variable)

Exit codes: 0 = all targeted instances taken over; 1 = at least one failure.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_API_BASE = (os.environ.get("LIGHTVELA_API")
                    or "https://api.lightvela.ai/v1")
DEFAULT_TOKEN_FILE = "tokens.txt"
DEFAULT_TS_FILE = "tailscale.key"
DEFAULT_SSH_KEY = Path.home() / ".ssh" / "id_ed25519"
DEFAULT_USER = "agentuser"


# ────────────────────────────────────────────────────────────────────
# Errors
# ────────────────────────────────────────────────────────────────────

class ApiError(RuntimeError):
    """A request that did not produce a usable result (401, 404, network)."""

    def __init__(self, status: int, message: str, body: str = ""):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {message}")


class ExecFailed(RuntimeError):
    """A command that RAN and returned non-zero.

    The API reports this as HTTP 500 ``DEBUG_EXEC_FAILED`` with the true exit
    code and the full output inside ``details``. That is a normal result, not a
    transport failure, so it is carried rather than swallowed.
    """

    def __init__(self, output: str, exit_code: int, details: dict | None = None):
        self.output = output
        self.exit_code = exit_code
        self.details = details or {}
        super().__init__(f"command failed with exit code {exit_code}")


# ────────────────────────────────────────────────────────────────────
# HTTP
# ────────────────────────────────────────────────────────────────────

def _opener():
    """Never inherit a machine-wide proxy for a call to a public API."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(method: str, url: str, token: str, body: dict | None = None,
            timeout: int = 30) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("authorization", f"Bearer {token}")
    req.add_header("cookie", f"lc_session={token}")
    req.add_header("accept", "application/json")
    if data is not None:
        req.add_header("content-type", "application/json")

    try:
        with _opener().open(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        exec_failure = _as_exec_failure(raw)
        if exec_failure is not None:
            raise exec_failure from None
        message = raw[:200]
        try:
            parsed = json.loads(raw)
            message = parsed.get("error") or parsed.get("message") or message
        except Exception:
            pass
        if e.code == 401:
            message += ("  <- token rejected. If it is fresh, the API base is"
                        " probably wrong (CN vs intl): pass --api")
        raise ApiError(e.code, message, raw) from None
    except urllib.error.URLError as e:
        raise ApiError(0, f"network error: {e.reason}") from None

    try:
        parsed = json.loads(raw)
    except Exception:
        raise ApiError(0, f"non-JSON response: {raw[:200]}", raw) from None

    # Some gateways report errors with HTTP 200 and an {"error": ...} body.
    # Treating that as "no data" is how a dead token becomes a silent success.
    if isinstance(parsed, dict) and parsed.get("error") and "data" not in parsed:
        raise ApiError(400, str(parsed["error"]), raw)
    return parsed


def _as_exec_failure(raw: str) -> ExecFailed | None:
    """Recognise DEBUG_EXEC_FAILED and recover (output, exit_code)."""
    try:
        parsed = json.loads(raw)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    details = parsed.get("details")
    if not isinstance(details, dict) or details.get("exit_code") is None:
        return None
    try:
        code = int(details["exit_code"])
    except (TypeError, ValueError):
        return None
    return ExecFailed(details.get("output") or "", code, details)


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

def list_instances(token: str, api_base: str) -> list[dict]:
    d = request("GET", f"{api_base}/instances", token)
    data = d.get("data") or {}
    items = data.get("items") if isinstance(data, dict) else data
    return items if isinstance(items, list) else []


def exec_cmd(token: str, api_base: str, instance_id: str, command: str,
             timeout: int = 120, user: str = DEFAULT_USER) -> tuple[str, int]:
    """Run a command through debug/exec.

    Returns ``(output, exit_code)`` and never raises for a command that ran and
    failed -- inspecting a non-zero exit is a legitimate thing to do (``command
    -v tailscale``, ``sudo -n true``). Use :func:`run` when a failure should
    abort the current step.

    The API hands back an authoritative ``data.exit_code``; using it means a
    failing step is detected by its real status rather than by the presence of
    an ``echo ...DONE`` marker, which is printed even when every preceding
    command in the chain failed.
    """
    try:
        d = request("POST", f"{api_base}/instances/{instance_id}/debug/exec",
                    token, body={"command": command, "run_as_user": user},
                    timeout=timeout)
    except ExecFailed as e:
        # A non-zero exit arrives as HTTP 500 DEBUG_EXEC_FAILED -- a result,
        # not a transport error.
        return e.output, e.exit_code

    data = d.get("data") or {}
    out = data.get("output")
    if out is None:
        out = data.get("stdout") or ""
    if not isinstance(out, str):
        out = json.dumps(out, ensure_ascii=False)
    code = data.get("exit_code")
    try:
        code = int(code)
    except (TypeError, ValueError):
        # Fall back to the status string when no exit code is present.
        status = str(data.get("status") or "").upper()
        code = 0 if status in ("SUCCESS", "OK", "SUCCEEDED") else 1
    return out, code


def run(token: str, api_base: str, iid: str, command: str,
        timeout: int = 120, user: str = DEFAULT_USER) -> str:
    """Run a step and fail loudly on a non-zero exit."""
    out, code = exec_cmd(token, api_base, iid, command, timeout, user)
    if code != 0:
        raise ExecFailed(out, code)
    return out


# ────────────────────────────────────────────────────────────────────
# Take-over pipeline
# ────────────────────────────────────────────────────────────────────

HARDENING_CONF = """\
PasswordAuthentication no
PermitRootLogin no
KbdInteractiveAuthentication no
MaxAuthTries 3
"""

HARDENING_PATH = "/etc/ssh/sshd_config.d/99-takeover-hardening.conf"


def hardening_command() -> str:
    """Build the shell that writes the hardening drop-in.

    A quoted heredoc is used deliberately. The previous implementation passed
    ``json.dumps(HARDENING_CONF)`` to ``printf '%s\\n'``; because the JSON form
    escapes newlines and POSIX ``printf %s`` does not interpret escapes, the
    file landed as a single line with literal backslash-n, and sshd refused to
    start (``unsupported option "no\\nPermitRootLogin"``). The restart then
    failed silently and the box kept running its original configuration.
    """
    return (
        f"sudo tee {HARDENING_PATH} >/dev/null <<'LV_EOF'\n"
        f"{HARDENING_CONF}"
        "LV_EOF\n"
        # cloud-init images ship PasswordAuthentication yes in these files
        "sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/;"
        "s/^PermitRootLogin .*/PermitRootLogin no/' "
        "/etc/ssh/sshd_config /etc/ssh/sshd_config.d/50-cloud-init.conf 2>/dev/null; "
        # validate BEFORE touching the running daemon
        "sudo sshd -t"
    )


def takeover(token: str, api_base: str, inst: dict, pubkey: str, authkey: str,
             hostname: str, user: str = DEFAULT_USER,
             dry_run: bool = False) -> tuple[str | None, str | None]:
    """Run the full take-over pipeline. Returns (tailnet_ip, error)."""
    iid = inst["instance_id"]
    name = inst.get("name") or iid[:8]

    # 1 ── sudo sanity check
    out, _ = exec_cmd(token, api_base, iid,
                      "sudo -n true 2>/dev/null && echo SUDO_OK || echo SUDO_FAIL",
                      user=user)
    if "SUDO_OK" not in out:
        return None, f"no sudo access ({out[:60]})"

    if dry_run:
        _, ts_code = exec_cmd(token, api_base, iid,
                              "command -v tailscale >/dev/null 2>&1",
                              user=user)
        print(f"[{name}] dry-run: sudo ok; tailscale installed="
              f"{ts_code == 0}; would use hostname lvp-{name}")
        return None, None

    # 2+3 ── inject pubkey, start sshd
    q = shlex.quote
    setup = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f"grep -qF {q(pubkey)} ~/.ssh/authorized_keys 2>/dev/null "
        f"|| echo {q(pubkey)} >> ~/.ssh/authorized_keys; "
        "chmod 600 ~/.ssh/authorized_keys; "
        "sudo mkdir -p /run/sshd; "
        "pgrep -x sshd >/dev/null || sudo /usr/sbin/sshd; "
        # real check: verify the daemon is actually listening, not that the
        # chain reached its final echo
        "pgrep -x sshd >/dev/null"
    )
    try:
        run(token, api_base, iid, setup, user=user)
    except ExecFailed as e:
        return None, f"ssh key/sshd setup failed: {e.output.strip()[:80]}"

    # 4 ── harden sshd (validated before the daemon is touched)
    try:
        run(token, api_base, iid, hardening_command(), user=user)
    except ExecFailed as e:
        # `sshd -t` rejected the config: drop the bad drop-in so the box is not
        # left in a state where sshd cannot start at all.
        exec_cmd(token, api_base, iid,
                 f"sudo rm -f {HARDENING_PATH} && sudo sshd -t", user=user)
        return None, ("ssh hardening rejected by `sshd -t`; drop-in removed: "
                      f"{e.output.strip()[:160]}")

    try:
        run(token, api_base, iid,
            f"sudo passwd -l {q(user)} >/dev/null 2>&1; "
            "sudo ufw default deny incoming >/dev/null 2>&1; "
            "sudo ufw default allow outgoing >/dev/null 2>&1; "
            "sudo ufw allow in on tailscale0 >/dev/null 2>&1; "
            "sudo ufw --force enable >/dev/null 2>&1; "
            "(sudo systemctl restart ssh || sudo systemctl restart sshd); "
            "systemctl is-active --quiet ssh || systemctl is-active --quiet sshd"
            , user=user)
    except ExecFailed as e:
        return None, f"ssh restart/firewall failed: {e.output.strip()[:80]}"

    # 5 ── install tailscale if missing, and confirm the binary exists
    try:
        run(token, api_base, iid,
            "if ! command -v tailscale >/dev/null 2>&1; then "
            "curl -fsSL https://tailscale.com/install.sh | sh; fi; "
            "command -v tailscale >/dev/null 2>&1"
            , user=user)
    except ExecFailed as e:
        return None, ("tailscale install failed (no tailscale binary "
                      f"afterwards): {e.output.strip()[:120]}")

    # 6 ── join tailnet (reusable authkey, no manual approval)
    # --ssh=false: Tailscale SSH would add a credential-less "none" auth path
    try:
        out = run(token, api_base, iid,
                  f"sudo tailscale up --ssh=false --authkey={q(authkey)} "
                  f"--hostname={q(hostname)} --reset >/dev/null 2>&1; "
                  "tailscale ip -4 | head -1",
                  timeout=90, user=user)
    except ExecFailed as e:
        return None, f"tailscale join failed ({e.output.strip()[:80]})"

    ts_ip = out.strip().splitlines()[-1].strip() if out.strip() else ""
    if not ts_ip.startswith("100."):
        return None, f"tailscale join failed ({out[:80]})"

    return ts_ip, None


def ssh_check(ts_ip: str, key: Path, user: str = DEFAULT_USER) -> bool:
    try:
        r = subprocess.run(
            ["ssh", "-i", str(key), "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
             f"{user}@{ts_ip}", "echo SSH_OK_$(hostname)"],
            capture_output=True, text=True, timeout=25)
    except subprocess.TimeoutExpired:
        return False
    return "SSH_OK_" in r.stdout


# ────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Take over LightVela sandbox instances via debug/exec.")
    ap.add_argument("--api", default=DEFAULT_API_BASE,
                    help=f"API base (default: {DEFAULT_API_BASE}); CN is "
                         "https://api.lightvela.com/v1")
    ap.add_argument("--token-file", default=DEFAULT_TOKEN_FILE,
                    help="file with one bearer token per line (default: tokens.txt)")
    ap.add_argument("--ts-file", default=DEFAULT_TS_FILE,
                    help="file containing the Tailscale authkey (default: tailscale.key)")
    ap.add_argument("--key", default=str(DEFAULT_SSH_KEY),
                    help="SSH private key path; auto-generated if missing")
    ap.add_argument("--only", help="comma-separated instance names to process")
    ap.add_argument("--user", default=DEFAULT_USER,
                    help=f"SSH user (default: {DEFAULT_USER})")
    ap.add_argument("--dry-run", action="store_true",
                    help="read-only: verify sudo and report; change nothing")
    args = ap.parse_args()

    api_base = args.api.rstrip("/")
    key_path = Path(args.key).expanduser()

    authkey = ""
    pubkey = ""
    if not args.dry_run:
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

    print(f"[api] {api_base}")
    for tok in tokens:
        try:
            instances = list_instances(tok, api_base)
        except ApiError as e:
            # A rejected token must not look like "nothing to do".
            print(f"[token {tok[:8]}…] ✗ {e}")
            results.append((f"token {tok[:8]}…", "-", "api-error"))
            failures += 1
            continue

        if not instances:
            print(f"[token {tok[:8]}…] no instances visible")
            continue

        for inst in instances:
            name = inst.get("name") or inst["instance_id"][:8]
            if only and name not in only:
                continue
            if inst.get("status") != "Running":
                print(f"[{name}] status={inst.get('status')} — skipped")
                continue

            print(f"[{name}] taking over {inst['instance_id']} ...")
            try:
                ts_ip, err = takeover(tok, api_base, inst, pubkey, authkey,
                                      f"lvp-{name}", args.user, args.dry_run)
            except ApiError as e:
                ts_ip, err = None, str(e)

            if args.dry_run and err is None:
                results.append((name, "-", "dry-run ok"))
                continue
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
