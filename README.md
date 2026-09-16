# LightVela Takeover

Take full control of [LightVela](https://lightvela.ai) sandbox instances through
their debug/exec API — automated SSH provisioning, hardening, and private
tailnet access with zero manual steps.

## What it does

For every LightVela instance found across your token list, the script:

1. **Verifies sudo** access through the instance exec endpoint
2. **Generates a fresh ed25519 SSH keypair** (or reuses an existing one via `--key`)
3. **Injects the public key** into the instance's `authorized_keys` and starts `sshd`
4. **Hardens the box** — password auth disabled, root login disabled,
   UFW default-deny with tailscale0-only inbound, agent user password locked
5. **Installs Tailscale** and joins your tailnet with a reusable auth key
6. **Verifies** end-to-end SSH connectivity over the tailnet IP

Result: a fleet of boxes reachable only through your private tailnet,
keyed exclusively with your private key.

```
$ python lv_takeover.py
[key] generated new keypair: /home/you/.ssh/id_ed25519
[worker1] taking over ins-a1b2c3... ...
[worker1] ✓ tailnet 100.x.y.z — ssh OK
[worker2] taking over ins-d4e5f6... ...
[worker2] ✓ tailnet 100.x.y.z — ssh OK

═══ SUMMARY ═══
worker1        100.x.y.z          ok
worker2        100.x.y.z          ok
```

## Why this is safe

| Layer | Effect |
|---|---|
| UFW `deny incoming` + `allow tailscale0` | Public internet cannot reach port 22 at all |
| `PasswordAuthentication no` | Password brute-force is impossible |
| `PermitRootLogin no` | Root cannot be targeted directly |
| `passwd -l agentuser` | Agent account is password-locked |
| Tailscale `--ssh=false` | Removes Tailscale's credential-less "none" auth path |
| Single ed25519 key | Only your private key opens the door |

Defense in depth: five independent layers, each verified after provisioning.

## Requirements

- Python 3.10+
- `curl` on PATH
- `ssh` / `ssh-keygen` on PATH (Windows: OpenSSH via Git for Windows works)
- A Tailscale account with a **reusable auth key**
  ([generate here](https://login.tailscale.com/admin/settings/keys) — check *Reusable*)

## Setup

```bash
git clone <this-repo> && cd lightvela-takeover

# 1. Tokens — one LightVela bearer token per line (chmod 600 recommended)
cp tokens.txt.example tokens.txt
$EDITOR tokens.txt

# 2. Tailscale authkey — single line
echo "tskey-auth-xxxxx -f" > tailscale.key
chmod 600 tailscale.key
```

**Where to get a bearer token:** open the LightVela dashboard, DevTools →
Network tab → any API request → copy the `authorization: Bearer …` header.

Both credential files are already covered by `.gitignore`.

## Usage

```bash
# process every token in tokens.txt (default)
python lv_takeover.py

# reuse an existing keypair instead of generating one
python lv_takeover.py --key ~/.ssh/id_ed25519

# only specific instance names
python lv_takeover.py --only prod,worker1

# custom files / ssh user
python lv_takeover.py --token-file my_tokens.txt --ts-file my_ts.key --user ubuntu
```

Exit code `0` = every targeted instance provisioned; `1` = at least one failure.

## Connecting afterwards

Any SSH client, via tailnet IP:

```bash
ssh -i ~/.ssh/id_ed25519 agentuser@100.x.y.z
```

GUI users: point MobaXterm/Termius at the tailnet IP, username `agentuser`,
private key = the generated one. Tailscale must be running on your machine.

## Token rotation

LightVela session tokens rotate. If `debug/exec` starts returning 401,
grab a fresh token from DevTools and update the line in `tokens.txt` —
nothing in the script itself needs to change.

## Disclaimer

This tool automates provisioning of compute **you already have access to**
(sandboxes on your own LightVela accounts). Use it only against instances
you own. Standard SSH hardening practices are applied automatically, but you
are responsible for the security posture of your tailnet and key files.
