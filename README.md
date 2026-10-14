# lightvela

Automate SSH provisioning for LightVela sandbox instances.

Reads a list of session tokens, finds every running instance, and sets each
one up for SSH access over Tailscale. No dashboard clicking, one command.

## What it does

Per instance:

1. Runs setup commands through the debug/exec API
2. Adds your SSH public key to `authorized_keys`, starts sshd
3. Disables password auth and root login, enables UFW (tailscale0 only)
4. Installs Tailscale if missing and joins your tailnet with an auth key
5. Checks SSH connectivity over the tailnet IP

## Files

```
lv_takeover.py        the script
tokens.txt            your LightVela bearer tokens, one per line (not in git)
tailscale.key         reusable Tailscale auth key (not in git)
```

Get a token: LightVela dashboard → DevTools → Network → copy the `Bearer` value.
Get an authkey: [Tailscale admin](https://login.tailscale.com/admin/settings/keys), generate one with **Reusable** checked.

## Usage

```bash
pip install nothing   # stdlib only, needs curl + ssh on PATH

python lv_takeover.py                     # all tokens in tokens.txt
python lv_takeover.py --only worker1      # specific instances
python lv_takeover.py --key ~/.ssh/id_ed25519   # reuse existing keypair
python lv_takeover.py --dry-run           # read-only: check sudo, change nothing
```

Output:

```
[api] https://api.lightvela.ai/v1
[worker1] taking over ins-a1b2c3... ...
[worker1] ✓ tailnet 100.x.y.z — ssh OK

═══ SUMMARY ═══
worker1        100.x.y.z   ok
```

Then connect:

```bash
ssh -i ~/.ssh/id_ed25519 agentuser@100.x.y.z
```

## Choosing the API base

The CN and international consoles are separate deployments on separate API
hosts. **A token from one is rejected with HTTP 401 by the other**, which looks
exactly like an expired token and sends you off to grab a fresh one for no
reason. Set the right base once:

| Console you signed up on | API base |
|---|---|
| lightvela.ai (international) | `https://api.lightvela.ai/v1` (default) |
| lightvela.com / lightvela.tencent.com (CN) | `https://api.lightvela.com/v1` |

```bash
python lv_takeover.py --api https://api.lightvela.com/v1
export LIGHTVELA_API=https://api.lightvela.com/v1
```

## Notes

- Tokens rotate; if the script gets 401s, grab a fresh one from DevTools.
- Requires Python 3.10+.
- Only use this on instances you own.
- MIT licensed.

## Hardening is validated before it is applied

The script writes `/etc/ssh/sshd_config.d/99-takeover-hardening.conf`, runs
`sudo sshd -t` against it, and only then restarts the daemon. If the config is
rejected the drop-in is removed and the instance is reported as failed, so a bad
config can never leave a box with a dead SSH daemon.
