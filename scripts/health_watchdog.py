#!/usr/bin/env python3
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from urllib import request, error


BASE_DIR = "/root/flash-note"
STATE_FILE = os.path.join(BASE_DIR, "data", "health_watchdog_state.json")


def getenv_bool(name: str, default: bool) -> bool:
    raw = str(os.getenv(name, "1" if default else "0")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def now_ts() -> int:
    return int(time.time())


def load_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    return {}


def save_state(data: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = f"{STATE_FILE}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_FILE)


def check_service_active(name: str) -> tuple[bool, str]:
    proc = subprocess.run(
        ["systemctl", "is-active", name],
        capture_output=True,
        text=True,
        check=False,
    )
    state = (proc.stdout or proc.stderr or "").strip()
    return (proc.returncode == 0 and state == "active"), f"{name}={state or 'unknown'}"


def check_healthz(url: str, timeout_sec: float, verify_tls: bool, expected_status: str) -> tuple[bool, str]:
    ctx = None
    if url.startswith("https://") and not verify_tls:
        ctx = ssl._create_unverified_context()

    req = request.Request(url=url, method="GET")
    req.add_header("User-Agent", "flash-note-health-watchdog/1.0")
    req.add_header("Accept", "application/json")

    try:
        with request.urlopen(req, timeout=timeout_sec, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status_code = int(getattr(resp, "status", 0) or 0)
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return False, f"healthz_http_error code={exc.code} body={body[:200]}"
    except Exception as exc:
        return False, f"healthz_request_error err={exc}"

    if status_code != 200:
        return False, f"healthz_bad_status_code code={status_code} body={body[:200]}"
    try:
        payload = json.loads(body)
    except Exception as exc:
        return False, f"healthz_invalid_json err={exc} body={body[:200]}"

    actual = str(payload.get("status", "")).strip().lower()
    expect = str(expected_status).strip().lower()
    if actual != expect:
        return False, f"healthz_bad_payload status={actual or '-'} expected={expect}"
    return True, "healthz=ok"


def send_webhook(webhook_url: str, text: str, level: str, details: list[str]) -> tuple[bool, str]:
    if not webhook_url:
        return True, "webhook_skipped"

    payload = {
        "text": text,
        "level": level,
        "host": socket.gethostname(),
        "time": now_ts(),
        "details": details,
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = request.Request(url=webhook_url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "flash-note-health-watchdog/1.0")
    try:
        with request.urlopen(req, timeout=5.0) as resp:
            code = int(getattr(resp, "status", 0) or 0)
            if 200 <= code < 300:
                return True, f"webhook_sent code={code}"
            return False, f"webhook_bad_code code={code}"
    except Exception as exc:
        return False, f"webhook_error err={exc}"


def main() -> int:
    healthz_url = str(os.getenv("APP_HEALTHCHECK_URL", "https://127.0.0.1/healthz")).strip()
    timeout_sec = float(os.getenv("APP_HEALTHCHECK_TIMEOUT_SEC", "5.0"))
    verify_tls = getenv_bool("APP_HEALTHCHECK_VERIFY_TLS", False)
    expected_status = str(os.getenv("APP_HEALTHCHECK_EXPECTED_STATUS", "ok")).strip()
    require_nginx = getenv_bool("APP_HEALTHCHECK_REQUIRE_NGINX", True)
    alert_webhook = str(os.getenv("APP_ALERT_WEBHOOK_URL", "")).strip()
    alert_min_interval_sec = int(os.getenv("APP_ALERT_MIN_INTERVAL_SEC", "600"))
    notify_recovery = getenv_bool("APP_ALERT_NOTIFY_RECOVERY", True)

    checks: list[tuple[bool, str]] = []
    checks.append(check_service_active("flash-note.service"))
    if require_nginx:
        checks.append(check_service_active("nginx.service"))
    checks.append(check_healthz(healthz_url, timeout_sec, verify_tls, expected_status))

    failures = [msg for ok, msg in checks if not ok]
    state = load_state()
    prev_status = str(state.get("last_status", "unknown"))
    ts = now_ts()

    if failures:
        summary = "; ".join(failures)
        msg = f"[ALERT] flash-note health degraded host={socket.gethostname()} details={summary}"
        print(msg, file=sys.stderr)

        last_alert_ts = int(state.get("last_alert_ts", 0) or 0)
        should_alert = (ts - last_alert_ts) >= alert_min_interval_sec
        if should_alert:
            ok, webhook_msg = send_webhook(alert_webhook, msg, "error", failures)
            print(f"[watchdog] {webhook_msg}", file=sys.stderr)
            state["last_alert_ts"] = ts
            state["last_alert_ok"] = bool(ok)
        else:
            print(
                f"[watchdog] alert_suppressed cooldown_left={alert_min_interval_sec - (ts - last_alert_ts)}s",
                file=sys.stderr,
            )

        state["last_status"] = "degraded"
        state["last_error"] = summary
        state["last_check_ts"] = ts
        save_state(state)
        return 1

    # success path
    msg = f"[OK] flash-note health ok host={socket.gethostname()}"
    print(msg)
    if prev_status == "degraded" and notify_recovery:
        recovery_msg = f"[RECOVERY] flash-note health restored host={socket.gethostname()}"
        ok, webhook_msg = send_webhook(alert_webhook, recovery_msg, "info", ["recovered"])
        print(f"[watchdog] {webhook_msg}")
        state["last_recovery_alert_ts"] = ts
        state["last_recovery_alert_ok"] = bool(ok)

    state["last_status"] = "ok"
    state["last_error"] = ""
    state["last_check_ts"] = ts
    save_state(state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
