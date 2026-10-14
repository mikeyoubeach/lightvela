#!python3
"""End-to-end validation of the hardening step against a REAL sandbox.

Opt-in: this talks to a live instance, so it needs credentials and skips
itself when they are absent.

    set LIGHTVELA_TOKEN=<session token>
    set LIGHTVELA_INSTANCE=ins-xxxxxxxx
    set LIGHTVELA_API=https://api.lightvela.com/v1     (CN; default is intl)
    py -3 tests/test_hardening_live.py

Exercises the exact command the fixed script would run, but with the drop-in
path redirected to a scratch file and `sshd -t` pointed at that file, so the
live sandbox's own SSH configuration is never touched.

Proves: (a) the old form is rejected by the real sshd, (b) the new form is
accepted by it.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import lv_takeover as lv  # noqa: E402

TOK = os.environ.get("LIGHTVELA_TOKEN", "").strip()
IID = os.environ.get("LIGHTVELA_INSTANCE", "").strip()
API = os.environ.get("LIGHTVELA_API", "https://api.lightvela.ai/v1").rstrip("/")

if not TOK or not IID:
    print("SKIP: set LIGHTVELA_TOKEN and LIGHTVELA_INSTANCE to run this test")
    print("      (it needs a live instance; nothing was sent)")
    sys.exit(0)

D = "$HOME/lvt_e2e"


def run(cmd, timeout=120):
    return lv.exec_cmd(TOK, API, IID, cmd, timeout=timeout)


print(f"=== target: {API} / {IID} ===")
out, code = run(f"rm -rf {D} && mkdir -p {D} && echo READY")
print(" ", out.strip(), f"(exit {code})")

print("\n=== (a) OLD form, exactly as the shipped script builds it ===")
old_cmd = (f"printf '%s\\n' {json.dumps(lv.HARDENING_CONF)} > {D}/old.conf; "
           f"od -c {D}/old.conf | head -2; "
           f"sudo sshd -t -f {D}/old.conf; echo \"OLD_SSHD_EXIT=$?\"")
out, code = run(old_cmd)
print(out)
old_rejected = "OLD_SSHD_EXIT=255" in out or "unsupported option" in out
print(f"  -> real sshd rejects the old file: {old_rejected}")

print("=== (b) NEW form, as the fixed script builds it ===")
fixed = lv.hardening_command().replace(lv.HARDENING_PATH, f"{D}/new.conf")
fixed = fixed.replace("sudo sshd -t", f"sudo sshd -t -f {D}/new.conf")
out, code = run(fixed)
print(" ", out.strip()[:200] or "(no output)")
new_ok = code == 0
print(f"  -> new file passes `sshd -t` (exit {code}): {new_ok}")

print("\n=== (c) contents comparison ===")
out, _ = run(f"echo '--- old (cat -A) ---'; cat -A {D}/old.conf; "
             f"echo '--- new (cat -A) ---'; cat -A {D}/new.conf")
print(out)

print("=== cleanup ===")
out, _ = run(f"rm -rf {D} && echo CLEANED")
print(" ", out.strip())

print()
ok = old_rejected and new_ok
print("RESULT:", "old form rejected AND new form accepted -- fix verified"
      if ok else "UNEXPECTED")
sys.exit(0 if ok else 1)
