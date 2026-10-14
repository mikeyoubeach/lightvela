#!python3
"""Unit checks for the fixed lv_takeover.py (no network)."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import lv_takeover as lv  # noqa: E402

FAILS = []


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if detail:
        print(f"         {detail}")
    if not cond:
        FAILS.append(label)


print("=== hardening_command() ===")
c = lv.hardening_command()
check("uses a quoted heredoc", "<<'LV_EOF'" in c)
check("loads the config text verbatim",
      "PasswordAuthentication no\nPermitRootLogin no" in c)
check("runs sshd -t before trusting the file", "sshd -t" in c)
check("no json-escaped newline is passed to printf",
      "printf" not in c)

# prove, with a real shell, that the file lands as 4 lines
bash = r"C:\Program Files\Git\bin\bash.exe"
if not Path(bash).exists():
    bash = "bash"
out_file = Path(tempfile.gettempdir()) / "lv_fix_check"
script = (lv.hardening_command()
          .replace("sudo tee " + lv.HARDENING_PATH,
                   "tee " + str(out_file).replace("\\", "/"))
          .replace("sudo sed", "sed")
          .replace("sudo sshd -t", "true"))
r = subprocess.run([bash, "-lc", script], capture_output=True, text=True,
                   encoding="utf-8", errors="replace")
if out_file.exists():
    lines = [l for l in out_file.read_text().splitlines() if l.strip()]
    check("fix writes 4 real lines (not one escaped line)", len(lines) == 4,
          " | ".join(lines))
    check("each directive is separate",
          lines[0] == "PasswordAuthentication no"
          and lines[3] == "MaxAuthTries 3")
else:
    check("fix produces an output file", False, r.stderr[:200])

print("\n=== demo: what the OLD code wrote, same shell ===")
OLD = (f"printf '%s\\n' {json.dumps(lv.HARDENING_CONF)}")
r = subprocess.run([bash, "-lc", OLD + " | cat -A"], capture_output=True,
                   text=True, encoding="utf-8", errors="replace")
old_out = r.stdout
check("old form is a single line with literal \\n",
      old_out.count("\n") == 1 and "\\n" in old_out, old_out.strip()[:100])

print("\n=== _as_exec_failure() ===")
raw = json.dumps({"code": "DEBUG_EXEC_FAILED", "message": "command execution failed",
                  "details": {"status": "EXIT STATUS 7", "exit_code": 7,
                              "output": "before\nboom\n"}})
e = lv._as_exec_failure(raw)
check("recovers the exit code", e is not None and e.exit_code == 7)
check("recovers the output", e is not None and e.output == "before\nboom\n")
check("returns None for an unrelated error",
      lv._as_exec_failure(json.dumps({"code": "SOMETHING_ELSE"})) is None)
check("returns None for non-JSON", lv._as_exec_failure("<html>502</html>") is None)

print("\n=== exec_cmd() prefers data.exit_code ===")
class FakeResp:
    def __init__(self, payload):
        self.payload = payload
    def read(self):
        return json.dumps(self.payload).encode()


def fake_request(method, url, token, body=None, timeout=30):
    return {"code": "OK", "data": {"status": "SUCCESS", "exit_code": 3,
                                   "output": "partial\n"}}


orig = lv.request
lv.request = fake_request
try:
    out, code = lv.exec_cmd("t", "http://x", "ins-1", "echo hi")
    check("exit_code 3 is used even though status says SUCCESS", code == 3,
          f"output={out!r} code={code}")
finally:
    lv.request = orig

print("\n=== run() raises on a non-zero exit ===")
lv.request = fake_request
try:
    lv.run("t", "http://x", "ins-1", "false")
    check("run() raises ExecFailed", False, "no exception")
except lv.ExecFailed as e:
    check("run() raises ExecFailed", e.exit_code == 3)
finally:
    lv.request = orig

print("\n=== list_instances() raises instead of returning [] ===")
def err_request(method, url, token, body=None, timeout=30):
    raise lv.ApiError(401, "unauthorized")
lv.request = err_request
try:
    lv.list_instances("t", "http://x")
    check("list_instances propagates ApiError", False, "returned instead")
except lv.ApiError as e:
    check("list_instances propagates ApiError", e.status == 401)
finally:
    lv.request = orig

print()
if FAILS:
    print(f"{len(FAILS)} FAILURE(S): {FAILS}")
    sys.exit(1)
print("ALL HELPER CHECKS PASSED")
