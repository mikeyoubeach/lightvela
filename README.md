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
```

Output:

```
[worker1] taking over ins-a1b2c3... ...
[worker1] ✓ tailnet 100.x.y.z — ssh OK

═══ SUMMARY ═══
worker1        100.x.y.z   ok
```

Then connect:

```bash
ssh -i ~/.ssh/id_ed25519 agentuser@100.x.y.z
```

## Notes

- Tokens rotate; if the script gets 401s, grab a fresh one from DevTools.
- Requires Python 3.10+.
- Only use this on instances you own.
- MIT licensed.
