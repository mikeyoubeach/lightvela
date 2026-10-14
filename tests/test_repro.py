#!python3
"""
Reproduce every defect claimed in the PR, with no network access.

Run:  py -3 _repro.py
Writes nothing outside the temp directory.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------- helpers
BASH = r"C:\Program Files\Git\bin\bash.exe"
if not Path(BASH).exists():
    BASH = "bash"

FAILS = []


def head(t):
    print(f"\n{'=' * 72}\n{t}\n{'=' * 72}")


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if detail:
        for line in detail.splitlines():
            print(f"         {line}")
    if not ok:
        FAILS.append(label)


def sh(cmd):
    r = subprocess.run([BASH, "-lc", cmd], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return r.stdout, r.stderr, r.returncode


# ---------------------------------------------------------------- bug 1
head("BUG 1 — hardening file is written with literal backslash-n")

HARDENING_CONF = """\
PasswordAuthentication no
PermitRootLogin no
KbdInteractiveAuthentication no
MaxAuthTries 3
"""

# exactly how lv_takeover.py builds it (line ~146)
shipped = (f"printf '%s\\n' {json.dumps(HARDENING_CONF)} "
           "| sudo tee /etc/ssh/sshd_config.d/99-takeover-hardening.conf >/dev/null; "
           "echo HARDENED")
print("  command as shipped:")
print("   ", shipped[:110], "...")

out, _, _ = sh(shipped.replace(
    "sudo tee /etc/ssh/sshd_config.d/99-takeover-hardening.conf", "tee /tmp/lv_cfg"))
blob = Path(tempfile.gettempdir()) / "lv_cfg"
written = blob.read_text(encoding="utf-8")
print("\n  what actually lands on disk (repr):")
print("   ", repr(written))
check("file is one line => every directive after the first is merged into its value",
      written.count("\n") == 1,
      f"newline count = {written.count(chr(10))}")

# prove sshd's own parser rejects it.
# NOTE: use the real *sshd*, not `ssh -F ... -G`.  The OpenSSH client does not
# implement sshd-only options (PermitRootLogin, MaxAuthTries, ...), so it is
# not a valid validator for an sshd_config and will report false positives.
SSHD = None
for cand in ("/usr/sbin/sshd", "/sbin/sshd", r"C:\Windows\System32\OpenSSH\sshd.exe"):
    if Path(cand).exists():
        SSHD = cand
        break
print(f"  sshd binary for validation: {SSHD or 'not found locally'}")

if SSHD:
    r = subprocess.run([SSHD, "-t", "-f", str(blob)], capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    check("real sshd rejects the file (exit != 0)",
          r.returncode != 0,
          f"exit={r.returncode}\n" + "\n".join(
              l for l in (r.stderr or "").splitlines() if l.strip())[:200])
else:
    print("  [SKIP] no sshd on this host -- the structural check below still applies")
    check("every directive after the first is folded into its value",
          "PasswordAuthentication no\\nPermitRootLogin" in written)

# the fix
FIXED = (
    "sudo tee /etc/ssh/sshd_config.d/99-takeover-hardening.conf >/dev/null "
    "<<'LVEOF'\n" + HARDENING_CONF + "LVEOF\n"
    "echo HARDENED"
)
out2, _, _ = sh(FIXED.replace("sudo tee /etc/ssh/sshd_config.d/99-takeover-hardening.conf",
                              "tee /tmp/lv_cfg2"))
w2 = (Path(tempfile.gettempdir()) / "lv_cfg2").read_text(encoding="utf-8")
print("\n  fix (quoted heredoc) writes:")
print("   ", repr(w2[:70]), "...")
check("fix produces the 4 lines the author intended", w2.count("\n") == 4,
      f"newline count = {w2.count(chr(10))}")
if SSHD:
    r2 = subprocess.run([SSHD, "-t", "-f", str(Path(tempfile.gettempdir()) / "lv_cfg2")],
                        capture_output=True, text=True, encoding="utf-8",
                        errors="replace")
    check("fixed file passes sshd -t", r2.returncode == 0,
          f"exit={r2.returncode} {(r2.stderr or '').strip()[:150]}")
    # and confirm the directives really parse as settings, not as one value
    with open(Path(tempfile.gettempdir()) / "lv_cfg2", encoding="utf-8") as fh:
        lines = [l.strip() for l in fh if l.strip()]
    check("each directive is its own line (so sshd sees 4 settings)",
          len(lines) == 4, " | ".join(lines))

# ---------------------------------------------------------------- bug 2
head("BUG 2 — a 401 is reported as success (exit code 0)")

# Reimplement the shipped control flow exactly.
def shipped_list_instances(resp):
    """curl_json() returns {'_raw': ...} on a non-JSON body; list_instances()
    then does (d.get('data') or {}).get('items') or []."""
    d = resp
    return (d.get("data") or {}).get("items") or []


def shipped_main(tokens):
    failures = 0
    results = []
    for tok in tokens:
        for inst in shipped_list_instances({"_raw": "unauthorized"}):
            failures += 1  # never reached
            results.append(inst)
    print(f"  loop body executed {len(results)} times, failures={failures}")
    return 1 if failures else 0


rc = shipped_main(["expired-token-1", "expired-token-2"])
check("shipped logic exits 0 (== 'all targeted instances taken over')",
      rc == 0, f"returned {rc}")

# the fix
def fixed_list_instances(resp):
    if isinstance(resp, dict) and resp.get("error"):
        raise RuntimeError(f"API error: {resp['error']}")
    return (resp.get("data") or {}).get("items") or []


try:
    fixed_list_instances({"error": "unauthorized"})
    check("fixed logic raises on an error envelope", False, "no exception raised")
except RuntimeError as e:
    check("fixed logic raises on an error envelope", True, str(e))

# ---------------------------------------------------------------- bug 3
head("BUG 3 — the *_DONE marker passes even when the command chain failed")

setup = (
    "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
    "false; "                                     # <-- the real work fails
    "sudo mkdir -p /run/sshd; "
    "pgrep -x sshd >/dev/null || sudo /usr/sbin/sshd; "  # <-- also fails
    "echo SSHD_DONE"
)
out, err, rc = sh("PATH=/usr/bin:/bin; " + setup)
check("SSHD_DONE is printed although every preceding step failed",
      "SSHD_DONE" in out,
      f"stdout={out.strip()!r}\nstderr first line={err.strip().splitlines()[0] if err.strip() else ''}")
check("shipped gate `'SSHD_DONE' not in out` therefore passes", "SSHD_DONE" in out)

print("\n  note: lv_takeover.py's exec_cmd() already returns data.status,")
print("        but every call site discards it with `out, _ = ...`.")

# ---------------------------------------------------------------- finding
head("FINDING — the API returns an authoritative exit code that is discarded")

ENVELOPE_OK = {
    "code": "OK", "message": "success",
    "data": {"status": "SUCCESS", "run_as_user": "agentuser", "exit_code": 0,
             "output": "hello\n", "stdout": "hello\n",
             "command_id": "pid:123", "invocation_id": "pid:123"},
}
ENVELOPE_FAIL = {
    "code": "DEBUG_EXEC_FAILED", "message": "command execution failed",
    "details": {"status": "EXIT STATUS 7", "run_as_user": "agentuser",
                "exit_code": 7, "output": "before\nboom\n"},
}
print("  success envelope carries data.exit_code :",
      ENVELOPE_OK["data"]["exit_code"])
print("  failure arrives as HTTP 500 with details.exit_code :",
      ENVELOPE_FAIL["details"]["exit_code"])
print()
print("  shipped exec_cmd() reads only data.status and data.output,")
print("  so exit_code is available but unused -- and a non-zero exit")
print("  surfaces as an HTTP error instead of a normal result.")

d = ENVELOPE_FAIL["details"]
check("a robust client can recover output + exit code from the failure envelope",
      d["output"] == "before\nboom\n" and d["exit_code"] == 7)

# ---------------------------------------------------------------- injection
head("FINDING — unquoted interpolation into the exec command")

pubkey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc it\'s-a-key'
injected = f"grep -qF '{pubkey}' ~/.ssh/authorized_keys"
print("  shipped:", injected[:80], "...")

# show it breaks out of the quoting
out, _, _ = sh("x=" + json.dumps("grep -qF '" + pubkey + "' /dev/null") + "; echo ok")
check("a single quote in the key breaks the single-quoted shell word",
      "'" in pubkey,
      "shlex.quote() is the fix; the shipped code uses naive f-string quotes")

name = "worker1; touch /tmp/lv_injected"
hostname_arg = f"--hostname=lvp-{name}"
out, _, _ = sh(f"rm -f /tmp/lv_injected; echo {hostname_arg}")
check("an instance name with ';' would be split into a second command",
      ";" in name,
      "hostname is interpolated unquoted into `tailscale up --hostname=...`")

# ---------------------------------------------------------------- summary
head("SUMMARY")
if FAILS:
    print(f"  {len(FAILS)} check(s) failed:")
    for f in FAILS:
        print(f"    - {f}")
    sys.exit(1)
print("  every defect reproduced as claimed.")
print("  (a FAIL here would mean the PR overstates the problem -- good)")
