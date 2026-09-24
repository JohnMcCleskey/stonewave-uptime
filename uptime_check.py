"""Outside uptime check for StoneWave's hosted desks.

    python3 uptime_check.py --targets targets.json --state .uptime-state/state.json

Every target gets one GET: no redirects followed, no cookies, no credentials.
The checker sends `User-Agent: stonewave-uptime/1` so its traffic is easy to
spot in logs. A separate hourly job reads this workflow's status from the
GitHub API and alerts when it has stopped running.

A target is down after `--min-failures` failed checks in a row (default 2, so
about 10 minutes on a 5-minute schedule). That posts one `uptime_down` alert,
and the first passing check afterwards posts `uptime_recovered`. Alerts are
signed and sent to the StoneWave ops relay, which delivers to ops@ and
Telegram. Alert ids are fixed per incident, so retries after a failed
delivery never double-alert.

State between runs lives in the Actions cache. When a run starts without it
(first run, or the cache came back empty), a single failure is enough to
alert, so a cache outage can't silence an outage. The cost: losing state
mid-incident can send a second `uptime_down` with a new id, and a recovery
for an incident alerted before the loss is not sent. The run log says when
state was missing.

Environment:
- SP_ALERT_URL and SP_ALERT_SECRET: the relay endpoint and its signing
  secret, both kept as GitHub secrets.
- UPTIME_DRILL: none | fail | recover | fallback. `fail` adds a check that
  cannot pass and alerts on its first failure (each `fail` drill is a new
  incident); `recover` points the same drill check at a healthy URL so it
  clears; `fallback` sends the failing drill's alert to an address that
  cannot resolve, so the run fails and GitHub's failed-run email is tested.

Exit code: 0 when every due alert was delivered, including runs where a site
is down but the alert got through. 1 when an alert was due and could not be
sent (relay down or not configured), or when the configuration is broken.
For a scheduled run, GitHub emails the failure to the user who last edited
the workflow's cron line (if they have Actions failure email on). That is
the fallback when the relay itself is down.

Standard library only. Output lists target names, HTTP statuses and alert
ids, never secrets or response bodies.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

USER_AGENT = "stonewave-uptime/1 (+https://github.com/JohnMcCleskey/stonewave-uptime)"
SIGNATURE_HEADER = "x-sp-alert-signature"
SUMMARY_CHARS = 300
TIMEOUT_SECONDS = 15
MAX_BODY_BYTES = 64 * 1024
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")
TENANT_RE = re.compile(r"^[A-Za-z0-9-]{3,64}$")
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
DRILL_NAME = "drill"
DRILL_MODES = ("none", "fail", "recover", "fallback")
UNREACHABLE_RELAY = "https://relay.invalid/ops-alert"  # .invalid never resolves (RFC 2606)


@dataclass(frozen=True)
class Target:
    name: str
    url: str
    status: tuple[int, ...]
    json_equals: dict
    location: str | None = None


@dataclass(frozen=True)
class Result:
    ok: bool
    detail: str


def log(message: str) -> None:
    print(message, flush=True)


def _iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).isoformat(timespec="seconds")


def _stamp(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# -- configuration ------------------------------------------------------------

def load_targets(path: Path) -> tuple[str, list[Target]]:
    """(tenant id, enabled targets). Raises ValueError on a malformed file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    tenant = str(data.get("tenant") or "")
    if not TENANT_RE.match(tenant):
        raise ValueError("targets.json: tenant must be 3-64 letters, digits or dashes")
    targets: list[Target] = []
    seen: set[str] = set()
    for raw in data.get("targets") or []:
        name = str(raw.get("name") or "")
        if not NAME_RE.match(name) or name == DRILL_NAME:
            raise ValueError(f"targets.json: bad target name {name!r}")
        if name in seen:
            raise ValueError(f"targets.json: duplicate target {name!r}")
        seen.add(name)
        url = str(raw.get("url") or "")
        if not url.startswith("https://"):
            raise ValueError(f"targets.json: {name} must use https")
        expect = raw.get("expect") or {}
        status = tuple(int(code) for code in (expect.get("status") or [200]))
        json_equals = expect.get("json") or {}
        if not isinstance(json_equals, dict):
            raise ValueError(f"targets.json: {name} expect.json must be an object")
        location = expect.get("location")
        if raw.get("enabled", True) is False:
            continue
        targets.append(Target(name, url, status, json_equals, str(location) if location else None))
    if not targets:
        raise ValueError("targets.json: no enabled targets")
    return tenant, targets


def drill_target(mode: str, targets: list[Target]) -> Target | None:
    """`fail` checks a path that can never return 200; `recover` checks a healthy one."""
    if mode not in {"fail", "recover", "fallback"}:
        return None
    base = targets[0]
    origin = re.match(r"^https://[^/]+", base.url).group(0)
    if mode in {"fail", "fallback"}:
        return Target(DRILL_NAME, f"{origin}/__stonewave-uptime-drill", (200,), {"ok": True})
    return Target(DRILL_NAME, base.url, base.status, base.json_equals, base.location)


# -- checking -----------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def fetch(url: str, timeout: float = TIMEOUT_SECONDS) -> tuple[int, dict, bytes]:
    """One GET. Returns (status, lower-cased headers, body up to 64 KB)."""
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(
        url, method="GET", headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/html"}
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read(MAX_BODY_BYTES)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read(MAX_BODY_BYTES)
        finally:
            exc.close()


def _health_fields(body: bytes) -> str:
    """"; store=…; revision=…" from a JSON body, safe characters only."""
    try:
        payload = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(payload, dict):
        return ""
    out = ""
    for key in ("store", "revision"):
        value = payload.get(key)
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", value):
            out += f"; {key}={value}"
    return out


def check(target: Target, fetcher: Callable[[str], tuple[int, dict, bytes]] | None = None) -> Result:
    try:
        status, headers, body = (fetcher or fetch)(target.url)
    except Exception as exc:  # timeouts, DNS, TLS, refused connections
        return Result(False, f"no response ({type(exc).__name__})")
    detail = f"HTTP {status}"
    if status not in target.status:
        if target.json_equals:
            detail += _health_fields(body)
        return Result(False, detail)
    if target.location is not None:
        location = headers.get("location", "")
        if location != target.location:
            return Result(False, f"{detail}; Location={location or '<missing>'}")
        detail += f"; Location={location}"
    if target.json_equals:
        try:
            payload = json.loads(body)
        except ValueError:
            return Result(False, f"{detail}; body is not JSON")
        if not isinstance(payload, dict):
            return Result(False, f"{detail}; body is not a JSON object")
        for key, want in target.json_equals.items():
            if payload.get(key) != want:
                return Result(False, f"{detail}; {key}={json.dumps(payload.get(key))}{_health_fields(body)}")
        detail += _health_fields(body)
    return Result(True, detail)


# -- alerting -----------------------------------------------------------------

def sign(secret: str, raw_body: str, t: int) -> str:
    """Same format the relay verifies: t=<unix>,v1=HMAC-SHA256(`t.body`)."""
    v1 = hmac.new(secret.encode("utf-8"), f"{t}.{raw_body}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"t={t},v1={v1}"


def post_alert(
    url: str,
    secret: str,
    alert: dict,
    opener: Callable = urllib.request.urlopen,
) -> tuple[bool, str]:
    """(delivered, note). Delivered includes the relay's "already delivered" answer."""
    raw = json.dumps(alert, separators=(",", ":"))
    request = urllib.request.Request(
        url,
        data=raw.encode("utf-8"),
        method="POST",
        headers={
            "content-type": "application/json",
            "user-agent": USER_AGENT,
            SIGNATURE_HEADER: sign(secret, raw, int(time.time())),
        },
    )
    try:
        with opener(request, timeout=TIMEOUT_SECONDS) as response:
            status = int(getattr(response, "status", None) or response.getcode())
            body = response.read(4096)
    except urllib.error.HTTPError as exc:
        return False, f"relay HTTP {exc.code}"
    except Exception as exc:
        return False, f"relay unreachable ({type(exc).__name__})"
    if not 200 <= status < 300:
        return False, f"relay HTTP {status}"
    try:
        data = json.loads(body or b"{}")
    except ValueError:
        data = {}
    if isinstance(data, dict) and data.get("duplicate"):
        return True, "already delivered"
    if isinstance(data, dict) and ("email" in data or "telegram" in data):
        return True, f"email={bool(data.get('email'))} telegram={bool(data.get('telegram'))}"
    return True, "delivered"


# -- state machine ------------------------------------------------------------

def load_state(path: Path) -> tuple[dict, bool]:
    """(state, restored). restored is False for a missing or unreadable file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"targets": {}}, False
    if not isinstance(data, dict) or not isinstance(data.get("targets"), dict):
        return {"targets": {}}, False
    return data, True


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(
    tenant: str,
    targets: list[Target],
    state: dict,
    now: datetime,
    min_failures: int = 2,
    fetcher: Callable[[str], tuple[int, dict, bytes]] | None = None,
    sender: Callable[[dict], tuple[bool, str]] | None = None,
    drill: Target | None = None,
) -> bool:
    """Check every target, update `state`, send due alerts. True when nothing due went unsent."""
    all_sent = True
    entries = state.setdefault("targets", {})
    checks = [(t, min_failures) for t in targets]
    if drill is not None:
        checks.append((drill, 1))
    for target, threshold in checks:
        entry = entries.get(target.name) or {}
        result = check(target, fetcher)
        log(f"{'PASS' if result.ok else 'FAIL'} {target.name}: {result.detail}")
        entry["last"] = {"at": _iso(now), "ok": result.ok, "detail": result.detail}
        if result.ok:
            if entry.get("alerted"):
                since = entry.get("since") or _iso(now)
                alert = {
                    "id": f"upok-{target.name}-{entry.get('stamp')}",
                    "tenantId": tenant,
                    "kind": "uptime_recovered",
                    "summary": (
                        f"{target.name} is back ({result.detail}). "
                        f"It was failing from {since} for {entry.get('fails', 0)} check(s). {target.url}"
                    )[:SUMMARY_CHARS],
                    "at": _iso(now),
                }
                if _send(alert, sender):
                    entry = {"last": entry["last"]}
                else:
                    all_sent = False
            else:
                entry = {"last": entry["last"]}
        else:
            if not entry.get("since"):
                entry["since"] = _iso(now)
                entry["stamp"] = _stamp(now)
            entry["fails"] = int(entry.get("fails") or 0) + 1
            if entry["fails"] >= threshold and not entry.get("alerted"):
                alert = {
                    "id": f"up-{target.name}-{entry['stamp']}",
                    "tenantId": tenant,
                    "kind": "uptime_down",
                    "summary": (
                        f"{target.name} is failing: {result.detail}. "
                        f"{entry['fails']} check(s) in a row since {entry['since']}. {target.url}"
                    )[:SUMMARY_CHARS],
                    "at": _iso(now),
                }
                if _send(alert, sender):
                    entry["alerted"] = alert["id"]
                else:
                    all_sent = False
        entries[target.name] = entry
    state["last_run"] = _iso(now)
    return all_sent


def _send(alert: dict, sender: Callable[[dict], tuple[bool, str]] | None) -> bool:
    if sender is None:
        log(f"ALERT NOT SENT {alert['kind']} {alert['id']}: relay not configured (SP_ALERT_URL / SP_ALERT_SECRET)")
        return False
    delivered, note = sender(alert)
    log(f"{'ALERT' if delivered else 'ALERT NOT SENT'} {alert['kind']} {alert['id']}: {note}")
    return delivered


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    parser = argparse.ArgumentParser(description="Outside uptime check for StoneWave's hosted desks.")
    parser.add_argument("--targets", default="targets.json")
    parser.add_argument("--state", default=".uptime-state/state.json")
    parser.add_argument("--min-failures", type=int, default=2)
    args = parser.parse_args(argv)

    try:
        tenant, targets = load_targets(Path(args.targets))
    except (OSError, ValueError) as exc:
        log(f"CONFIG ERROR: {exc}")
        return 1
    mode = (os.environ.get("UPTIME_DRILL") or "none").strip().lower()
    if mode not in DRILL_MODES:
        log("CONFIG ERROR: UPTIME_DRILL must be none, fail, recover or fallback")
        return 1

    url = (os.environ.get("SP_ALERT_URL") or "").strip()
    secret = (os.environ.get("SP_ALERT_SECRET") or "").strip()
    if mode == "fallback":
        log("DRILL fallback: the drill alert goes to an unreachable relay, so this run should fail")
        url, secret = UNREACHABLE_RELAY, secret or "fallback-drill"
    sender = (lambda alert: post_alert(url, secret, alert)) if url and secret else None
    if sender is None:
        log("WARNING: relay not configured; a failing target will fail this run instead of alerting")

    state_path = Path(args.state)
    state, restored = load_state(state_path)
    min_failures = max(1, args.min_failures)
    if not restored:
        log("WARNING: no saved state (first run or empty cache); alerting on the first failure this run")
        min_failures = 1
    if mode in {"fail", "fallback"}:
        state.get("targets", {}).pop(DRILL_NAME, None)  # every fail drill is a fresh incident
    all_sent = run(
        tenant,
        targets,
        state,
        now or datetime.now(timezone.utc),
        min_failures=min_failures,
        sender=sender,
        drill=drill_target(mode, targets),
    )
    save_state(state_path, state)
    return 0 if all_sent else 1


if __name__ == "__main__":
    sys.exit(main())
