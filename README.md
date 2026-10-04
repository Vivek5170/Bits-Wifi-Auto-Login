# BITS Wi-Fi Auto Login

Logs you in to the BITS captive portal automatically and rotates through
your accounts as daily quotas run out. Windows, macOS, Linux, no dependencies.

## Setup

Put your accounts in `credentials.txt`, one per line (`username password`):

```
f20xxxxxx Bits@xxxxxxxx
f20xxxxxx Bits@xxxxxxxx
```

Tune thresholds in `config.yaml` if needed (`switch_start_mb`,
`reset_time`, heartbeat settings).

Needs a direct route to the campus portal: if you use Cloudflare WARP,
exclude `172.16.0.0/12` from the tunnel (or turn WARP off on campus Wi-Fi).

## Run

```bash
python3 autologin.py            # start daemon
python3 autologin.py --seed 42  # reproducible shuffle order
```

Stop with Ctrl+C (`kill <PID>` for background runs).


## How this differs from a simple check-and-relogin script

A basic script only notices the internet is down and logs in again — so you
discover an exhausted quota exactly when your connection dies, then pay for a
fresh round of trial logins while offline.

This one reads the firewall's own quota meter (User Portal) independently of
the login session, so it acts *before* anything breaks:

- **Sweep-based rotation:** when a login is needed, it walks forward from the
  current account and takes the first usable one. While online it re-checks
  the active quota periodically and switches past `switch_start_mb`.
- **Random order, then linear:** the pool is shuffled once at startup (seeded),
  and every sweep walks forward from the current account, stopping at the
  first usable one. Searches stay minimal by design.
- **Off-campus aware:** leaving campus logs one line and waits quietly; on
  return it re-establishes its own account from where it left off.

## config.yaml values

| Key | Meaning |
|---|---|
| `credentials_file` | Account list (`username password` per line). |
| `failed_file` | Where wrong-password pairs are remembered. |
| `heartbeat_interval` | Seconds per main-loop beat; scheduler for everything. |
| `usage_check_heartbeats` | Check the active account's quota every N beats. |
| `ping_timeout` / `login_timeout` | Network timeouts. |
| `portal_host` | Firewall IP (`172.16.0.30`). |
| `switch_start_mb` | USED past this → sweep + switch accounts. |
| `reset_time` | Daily quota reset, 24h `"HH:MM"` — sweeps restart from #1 after it. |
| `random_seed` | Shuffle seed (`null` = time-based, `--seed N` overrides). |
