"""BITS Wi-Fi auto-login daemon. Simple design:

ONE heartbeat-driven main event loop, ONE account-selection function
(sweep), ONE captive-login operation:

1. Credentials are shuffled once; `curr` marks the active account and the
   start of the next sweep. A sweep only moves a LOCAL cursor; only a
   successful captive login changes `curr`.
2. Each heartbeat: off campus -> wait; no Internet (or no active account
   yet) -> sweep from `curr`, captive-login the candidate; Internet up ->
   count heartbeats, check the active account's quota every
   `usage_check_heartbeats`, sweep + switch past `switch_start_mb`.
3. Sweep classifies each account as wrong password (record pair, advance),
   usable (return candidate), quota exhausted (advance), or transient
   (retry same account with backoff, then restart the main loop).
4. Pool exhausted -> wait until reset_time, restart from account 0.
5. Only explicit wrong-password answers advance past an account; anything
   inconclusive retries in place and never touches the bad-password file.

All knobs live in config.yaml (flat key: value pairs, no deps needed).
Usage:
    python3 autologin.py                 # start daemon
    python3 autologin.py --seed 42       # reproducible shuffle order
"""
import http.cookiejar
import json
import logging
import os
import random
import re
import signal
import ssl
import sys
import time
from datetime import datetime, timedelta
from urllib.error import URLError
from urllib.parse import quote, urlencode
from urllib.request import (Request, build_opener, HTTPCookieProcessor,
                            HTTPSHandler, urlopen)

# Resolve data files against the script's own folder, so the daemon also
# works when launched from elsewhere (Task Scheduler, LaunchAgent, nohup).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def resolve(path):
    return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)

# ------------------------------- config ------------------------------------
# Knobs live in config.yaml (flat `key: value`, # comments allowed).
# Missing file or keys -> these defaults apply. No third-party deps needed.
_DEFAULTS = {
    "credentials_file": "credentials.txt",
    "heartbeat_interval": 10,
    "usage_check_heartbeats": 15,
    "ping_timeout": 4,
    "login_timeout": 10,
    "portal_host": "172.16.0.30",
    "switch_start_mb": 9500,
    "reset_time": "00:00",
    "random_seed": None,
    "failed_file": "failed.txt",
}


def _parse_value(raw):
    raw = raw.strip()
    if raw in ("null", "None", "~", ""):
        return None
    if raw.lower() in ("true", "yes"):
        return True
    if raw.lower() in ("false", "no"):
        return False
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    if (raw.startswith('"') and raw.endswith('"')) or \
       (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]
    return raw


def load_config(path="config.yaml"):
    cfg = dict(_DEFAULTS)
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line or ":" not in line:
                    continue
                key, _, raw = line.partition(":")
                key = key.strip()
                if key in cfg:
                    cfg[key] = _parse_value(raw)
    except FileNotFoundError:
        log.warning(" %s not found — using built-in defaults.", path)
    return cfg


CFG = load_config(resolve("config.yaml"))

CREDENTIALS_FILE = resolve(CFG["credentials_file"])
FAILED_FILE = resolve(CFG["failed_file"])
HEARTBEAT_INTERVAL = CFG["heartbeat_interval"]      # sec per main-loop beat
USAGE_CHECK_HEARTBEATS = CFG["usage_check_heartbeats"]  # beats between usage checks
PING_TIMEOUT = CFG["ping_timeout"]
LOGIN_TIMEOUT = CFG["login_timeout"]
PORTAL_HOST = CFG["portal_host"]
PORTAL_URL = f"http://{PORTAL_HOST}:8090"
LOGIN_URL = f"{PORTAL_URL}/login.xml"
USERPORTAL_BASE = f"https://{PORTAL_HOST}:65040/userportal"

SWITCH_START_MB = CFG["switch_start_mb"]      # USED crosses this -> sweep + switch
RESET_TIME = str(CFG["reset_time"])           # 24h "HH:MM" daily quota reset
RANDOM_SEED = CFG["random_seed"]              # None -> time seed (--seed N overrides)

RESTART = "restart"       # sweep outcome: back to the top of the main loop
EXHAUSTED = "exhausted"   # sweep outcome: full pool has nothing usable
MAX_SWEEP_RETRIES = 7     # Case-D retries per account before restarting loop

# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout),
              logging.FileHandler(resolve("autologin.log"))],
)
log = logging.getLogger()

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)  # live logs when redirected


def load_failed(path):
    """(username, password) pairs already proven wrong. A password edit in
    credentials.txt naturally stops matching, so fixed accounts get retried."""
    pairs = set()
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    pairs.add((parts[0], parts[1]))
    except FileNotFoundError:
        pass
    return pairs


def remember_failed(path, username, password):
    """Append a (user, password) pair, idempotently: re-marking the same pair
    (e.g. across daemon restarts) must not grow the file."""
    if (username, password) in load_failed(path):
        return
    with open(path, "a") as f:
        f.write(f"{username} {password}\n")


def compact_failed(path):
    """One-time squeeze: drop duplicate lines left by older versions."""
    try:
        with open(path) as f:
            lines = [l for l in (l.strip() for l in f) if l]
    except FileNotFoundError:
        return
    seen, unique = set(), []
    for line in lines:
        if line not in seen:
            seen.add(line)
            unique.append(line)
    if len(unique) != len(lines):
        with open(path, "w") as f:
            f.write("\n".join(unique) + "\n")
        log.info(" Compacted %s (%d -> %d).", path, len(lines), len(unique))


def mark_bad(pair, bad):
    if pair not in bad:
        bad.add(pair)
        remember_failed(FAILED_FILE, *pair)


def load_credentials(path):
    creds = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    creds.append((parts[0], parts[1]))
    except FileNotFoundError:
        log.error(" Credentials file '%s' not found.", path)
        sys.exit(1)
    if not creds:
        log.error(" No valid credentials found.")
        sys.exit(1)
    log.info(" Loaded %d credential(s) from %s", len(creds), path)
    return creds


def is_on_campus():
    try:
        urlopen(PORTAL_URL, timeout=PING_TIMEOUT)
        return True
    except Exception:
        return False


def is_internet_up():
    try:
        with urlopen("http://clients1.google.com/generate_204",
                      timeout=PING_TIMEOUT) as resp:
            return resp.status == 204
    except Exception:
        return False


def try_login(username, password):
    """Returns one of "ok" | "exceeded" | "failed" | "portal_down"."""
    data = {"mode": "191", "username": username, "password": password,
            "a": int(time.time() * 1000), "producttype": "0"}
    headers = {"Accept": "*/*", "Content-Type": "application/x-www-form-urlencoded",
               "Origin": PORTAL_URL, "Referer": f"{PORTAL_URL}/httpclient.html",
               "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/147.0.0.0 Safari/537.36")}
    try:
        req = Request(LOGIN_URL, data=urlencode(data).encode(),
                      headers=headers, method="POST")
        with urlopen(req, timeout=LOGIN_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (URLError, TimeoutError, OSError):
        return "portal_down"
    if "LIVE" in body:
        return "ok"
    low = body.lower()
    if "exceeded" in low:
        return "exceeded"
    if "invalid user name" in low:
        return "failed"
    log.warning(" Unknown portal response: %s", body[:200])
    return "portal_down"


def check_quota(username, password):
    """Read-only quota check via the user portal (never touches the session).

    Returns dict {used, remaining, allotted, renewal, current} (MB),
    {"badpass": True} for wrong credentials, or None on network trouble.
    """
    try:
        ctx = ssl._create_unverified_context()  # firewall self-signed cert
        op = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()),
                          HTTPSHandler(context=ctx))

        payload = json.dumps({"username": username, "password": password,
                              "languageid": "1"})
        req = Request(USERPORTAL_BASE + "/Controller",
                      data=f"mode=451&json={quote(payload)}".encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               "X-Requested-With": "XMLHttpRequest"})
        with op.open(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        try:
            auth = json.loads(body)
        except json.JSONDecodeError:
            log.warning(" Unknown user portal auth response: %s", body[:200])
            return None
        if auth.get("status") != 200:
            text = json.dumps(auth).lower()
            if "invalid" in text or "wrong" in text or "failed" in text:
                return {"badpass": True}
            if auth.get("status") == -1 or "login.jsp" in text:
                # Fresh auth rejected with a login redirect and no session.
                # Observed for wrong passwords (correct creds return 200);
                # timeouts stay transient, so a block never lands here.
                return {"badpass": True}
            log.warning(" User portal auth rejected transiently: %s", body[:200])
            return None

        idx = op.open(Request(
            USERPORTAL_BASE + "/webpages/myaccount/index.jsp",
            headers={"User-Agent": "Mozilla/5.0"}),
            timeout=15).read().decode("utf-8", errors="replace")
        csrf = re.search(r"c\$rFt0k3n\s*=\s*'([^']+)'", idx).group(1)

        # ?popup=0 is the exact request the browser's menu loader makes;
        # a plain page fetch returns empty.
        html = op.open(Request(
            USERPORTAL_BASE + "/webpages/myaccount/AccountStatus.jsp?popup=0",
            headers={"User-Agent": "Mozilla/5.0", "X-CSRF-Token": csrf,
                     "X-Requested-With": "XMLHttpRequest",
                     "Referer": USERPORTAL_BASE + "/webpages/myaccount/index.jsp"}),
            timeout=15).read().decode("utf-8", errors="replace")

        m = re.search(r"CycleDataTrasfer.{0,800}?([\d.]+)&nbsp;"
                      r".*?([\d.]+)&nbsp;.*?([\d.]+)&nbsp;"
                      r".*?([\d.]+)&nbsp;.*?([\d.]+)&nbsp;", html, re.S)
        m2 = re.search(r"DataTransferRenewal.{0,500}?(\d{2}/\d{2}/\d{4})", html, re.S)
        if not m:
            return None
        allotted, _last, current, total, remaining = map(float, m.groups())
        try:  # best-effort logout so portal sessions don't pile up
            op.open(Request(USERPORTAL_BASE +
                            "/webpages/logout.jsp?webclient=myaccount"),
                    timeout=10).read()
        except Exception:
            pass
        return {"used": total, "remaining": remaining, "allotted": allotted,
                "renewal": m2.group(1) if m2 else "?", "current": current}
    except Exception as e:
        log.warning(" Quota check failed for %s (%s).", username, type(e).__name__)
        return None


def login_as(order, i):
    user, pwd = order[i]
    log.info(" Trying account [%d/%d]: %s", i + 1, len(order), user)
    return user, try_login(user, pwd)


def retry_transient(user, fetch):
    """The ONE retry mechanism in the daemon. `fetch` returns None on a
    transient failure, any other value on a classified answer. Retries the
    SAME fetch with heartbeat-based exponential backoff (max 7 retries).
    Returns (True, value), or (False, None) when retries run out — the
    caller then returns RESTART to the top of the main loop."""
    for attempt in range(MAX_SWEEP_RETRIES + 1):
        value = fetch()
        if value is not None:
            return True, value
        if attempt == MAX_SWEEP_RETRIES:
            log.warning(" Operation failed for %s after %d retries — "
                        "restarting main loop.", user, MAX_SWEEP_RETRIES)
            return False, None
        log.warning(" Login unavailable for %s — retrying.", user)
        delay = min(
            HEARTBEAT_INTERVAL * (2 ** attempt),
            HEARTBEAT_INTERVAL * 12
        )
        time.sleep(delay)
    return False, None


def sweep(order, start, bad, exclude=None):
    """The ONLY account-selection mechanism. One forward pass from `start`,
    wrapping once; each account is inspected at most once per sweep.

    Uses a LOCAL cursor: persistent `curr` is never touched here.
    Returns (index, quota, "candidate"), (None, None, RESTART), or
    (None, None, EXHAUSTED).
    """
    n = len(order)
    skip = exclude or set()
    for k in range(n):
        i = (start + k) % n
        if i in skip:
            continue
        user, pwd = order[i]
        if (user, pwd) in bad:
            log.warning(" Skipping %s — wrong password.", user)
            continue
        ok, q = retry_transient(user, lambda: check_quota(user, pwd))
        if not ok:
            return None, None, RESTART
        if q.get("badpass"):
            log.warning(" Skipping %s — wrong password.", user)
            mark_bad((user, pwd), bad)
            continue
        if q["used"] >= SWITCH_START_MB:
            log.warning(" Skipping %s — quota exhausted.", user)
            continue
        return i, q, "candidate"
    return None, None, EXHAUSTED


def try_establish(order, start, bad):
    """One establishment round from `start`: sweep, then captive-login the candidate
    with the SAME retry mechanism. A classified captive failure continues
    from the NEXT account (failed pairs persist as bad, exceeded ones are
    excluded for this round only), so every round terminates. Only an
    explicit wrong password marks a credential bad; `curr` moves solely on
    login success. Returns ("ok", index, quota) | (RESTART,) | (EXHAUSTED,)."""
    n = len(order)
    exclude = set()
    s = start
    while True:
        idx, q, outcome = sweep(order, s, bad, exclude)
        if outcome == RESTART:
            return (RESTART,)
        if outcome == EXHAUSTED:
            return (EXHAUSTED,)
        user, pwd = order[idx]

        def attempt_login():
            _, res = login_as(order, idx)
            return None if res == "portal_down" else res

        ok, res = retry_transient(user, attempt_login)
        if not ok:
            return (RESTART,)
        if res == "ok":
            return ("ok", idx, q)
        if res == "failed":
            log.warning(" Skipping %s — wrong password.", user)
            mark_bad(order[idx], bad)
        else:  # exceeded: usable at portal, spent at captive; try next
            log.warning(" Skipping %s — quota exhausted.", user)
        exclude.add(idx)
        s = (idx + 1) % n


def parse_reset(s):
    try:
        h, m = str(s).split(":")
        h, m = int(h), int(m)
        assert 0 <= h < 24 and 0 <= m < 60
        return h, m
    except Exception:
        log.warning(" Bad reset_time %r — using 00:00.", s)
        return 0, 0


def seconds_until_reset(now=None):
    now = now or datetime.now()
    h, m = parse_reset(RESET_TIME)
    nxt = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)
    return (nxt - now).total_seconds(), nxt.strftime("%H:%M")


def wait_for_reset():
    """Pool exhausted: quotas refill only at reset_time. Internet coming
    back does NOT refill quota, so wait the full duration unconditionally."""
    secs, at = seconds_until_reset()
    log.error(" All accounts exhausted — waiting for reset at %s.", at)
    time.sleep(max(secs, 0))
    log.info(" Reset time reached — restarting from account #1.")


def run(order):
    compact_failed(FAILED_FILE)  # heal files written before dedup existed
    bad = load_failed(FAILED_FILE)  # (user, pwd) pairs; survives restarts
    if bad:
        log.info(" Skipping %d known-bad credential(s) from %s.",
                 len(bad), FAILED_FILE)
    curr = 0             # active account; also the next sweep's start
    active = None        # no account established yet (see startup rule below)
    usage_heartbeat_counter = 0
    was_on_campus = None  # log campus transitions only, not every heartbeat
    log.info(" Order: %s", ", ".join(u for u, _ in order))
    log.info(" Heartbeat %ss, usage check every %s heartbeats, "
             "switch at %sMB, reset at %s.",
             HEARTBEAT_INTERVAL, USAGE_CHECK_HEARTBEATS,
             SWITCH_START_MB, RESET_TIME)

    while True:  # the ONE main event loop
        on_campus = is_on_campus()
        if not on_campus:
            if was_on_campus is not False:
                log.info(" Not on campus — waiting.")
            was_on_campus = False
            time.sleep(HEARTBEAT_INTERVAL)
            continue
        if was_on_campus is False:
            log.info(" Back on campus.")
            active = None  # previous session did not survive; re-establish
        was_on_campus = True

        up = is_internet_up()

        # --- no Internet, or startup with no established account ------------
        # An already-present connection means nothing here: hotspot, LAN,
        # VPN, or an existing campus session are indistinguishable, so until
        # THIS daemon logs in, it always sweeps from `curr`.
        if not up or active is None:
            if not up:
                log.info(" Internet down — finding usable account.")
            outcome = try_establish(order, curr, bad)
            if outcome[0] == RESTART:
                time.sleep(HEARTBEAT_INTERVAL)
                continue
            if outcome[0] == EXHAUSTED:
                wait_for_reset()   # quotas refill only at reset
                curr, active, usage_heartbeat_counter = 0, None, 0
                continue
            _, idx, q = outcome
            curr = idx
            active = idx
            usage_heartbeat_counter = 0
            if not up:
                log.info(" Internet restored — logged in as %s.", order[idx][0])
            else:
                log.info(" Logged in as %s (%.0fMB used).", order[idx][0], q["used"])
            time.sleep(HEARTBEAT_INTERVAL)
            continue

        # --- Internet up on our own active account: usage watch -------------
        usage_heartbeat_counter += 1
        if usage_heartbeat_counter >= USAGE_CHECK_HEARTBEATS:
            usage_heartbeat_counter = 0
            user, pwd = order[active]
            q = check_quota(user, pwd)
            if q is None:
                log.warning(" Quota check unavailable for %s — retrying "
                            "on next check.", user)
            elif q.get("badpass"):
                mark_bad((user, pwd), bad)
                active = None  # password changed: re-establish next loop
            elif q["used"] >= SWITCH_START_MB:
                log.warning(" %s reached %.0fMB — sweeping for a new account.",
                            user, q["used"])
                outcome = try_establish(order, curr, bad)
                if outcome[0] == RESTART:
                    continue
                if outcome[0] == EXHAUSTED:
                    wait_for_reset()
                    curr, active, usage_heartbeat_counter = 0, None, 0
                    continue
                _, idx, nq = outcome
                curr = idx
                active = idx
                usage_heartbeat_counter = 0
                log.info(" Logged in as %s (%.0fMB used).", order[idx][0], nq["used"])

        time.sleep(HEARTBEAT_INTERVAL)


def main():
    seed = RANDOM_SEED
    if "--seed" in sys.argv and sys.argv.index("--seed") + 1 < len(sys.argv):
        seed = int(sys.argv[sys.argv.index("--seed") + 1])
    random.seed(seed if seed is not None else time.time())
    log.info(" Shuffle seed: %s", seed if seed is not None else "time-based")

    order = load_credentials(CREDENTIALS_FILE)
    random.shuffle(order)

    def handle_exit(sig, frame):
        print("\n\n Stopping auto-login daemon. Bye!")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_exit)

    log.info(" Auto-login daemon started. Press Ctrl+C to stop.\n")
    run(order)


if __name__ == "__main__":
    main()
