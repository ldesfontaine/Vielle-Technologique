import asyncio
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict

import uvicorn

from .api import create_app
from .collector.certfr import fetch_certfr
from .collector.cisa_kev import fetch_cisa_kev
from .collector.exploitdb import fetch_exploitdb
from .collector.github_advisories import fetch_github_advisories
from .collector.nvd import fetch_nvd
from .matcher import extract_cve_ids, load_tools, match_tools
from .models import alert_exists, init_db, insert_alert, set_meta, get_meta, list_alerts_since
from .notifier import send_ntfy_alert, send_ntfy_digest

DB_PATH = os.environ.get("DB_PATH", "/data/veille.db")
CRON_INTERVAL = int(os.environ.get("CRON_INTERVAL", "3600"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8094"))
NTFY_URL = os.environ.get("NTFY_URL", "").strip()
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "").strip()
DASHBOARD_ENABLED = os.environ.get("DASHBOARD_ENABLED", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
MANUAL_COLLECT_COOLDOWN = int(os.environ.get("MANUAL_COLLECT_COOLDOWN", "900"))

_manual_collect_lock = asyncio.Lock()
_last_manual_collect = 0.0

@asynccontextmanager
async def lifespan(_app):
    init_db(DB_PATH)
    task = asyncio.create_task(collector_loop())
    _app.state.collector_task = task
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def collect_once() -> Dict[str, object]:
    global _last_manual_collect

    now = time.time()
    remaining = MANUAL_COLLECT_COOLDOWN - (now - _last_manual_collect)
    if remaining > 0:
        return {
            "status": "cooldown",
            "message": "Manual collect cooldown active",
            "retry_in_seconds": int(remaining),
        }

    if _manual_collect_lock.locked():
        return {"status": "busy", "message": "Collect already running"}

    async with _manual_collect_lock:
        _last_manual_collect = time.time()
        result = await collect_cycle(manual=True)
        result["message"] = "Collect done"
        return result


app = create_app(
    DB_PATH,
    lifespan=lifespan,
    dashboard_enabled=DASHBOARD_ENABLED,
    collect_handler=collect_once,
)


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def normalize_alert(alert: Dict[str, object]) -> Dict[str, object]:
    title = str(alert.get("title", ""))
    description = str(alert.get("description", ""))
    text = f"{title} {description}"
    cves = extract_cve_ids(text)
    if not alert.get("cve_id") and cves:
        alert["cve_id"] = cves[0]

    if alert.get("cvss_score") is not None:
        alert["severity"] = severity_from_cvss(float(alert["cvss_score"]))
    elif not alert.get("severity"):
        alert["severity"] = "medium" if alert.get("cve_id") else "info"

    return alert


async def collect_cycle(manual: bool = False) -> Dict[str, object]:
    tools = load_tools()
    new_alerts: list[Dict[str, object]] = []
    inserted_count = 0

    last_fetch = {
        "nvd": get_meta(DB_PATH, "last_fetch_nvd"),
        "certfr": get_meta(DB_PATH, "last_fetch_certfr"),
        "github": get_meta(DB_PATH, "last_fetch_github"),
        "cisa": get_meta(DB_PATH, "last_fetch_cisa"),
        "exploitdb": get_meta(DB_PATH, "last_fetch_exploitdb"),
    }

    fetch_map = {
        "nvd": fetch_nvd,
        "certfr": fetch_certfr,
        "github": fetch_github_advisories,
        "cisa": fetch_cisa_kev,
        "exploitdb": fetch_exploitdb,
    }

    for key, fetcher in fetch_map.items():
        try:
            alerts = await fetcher(last_fetch.get(key))
        except Exception as exc:
            print(f"[collector] {key} error: {exc}")
            continue

        for alert in alerts:
            normalized = normalize_alert(alert)
            normalized["created_at"] = datetime.utcnow().isoformat()
            text = f"{normalized.get('title', '')} {normalized.get('description', '')}"
            matched = match_tools(text, tools)
            if not matched:
                continue
            normalized["matched_tools"] = matched

            if alert_exists(DB_PATH, normalized.get("cve_id"), str(normalized.get("link"))):
                continue

            should_notify = normalized.get("severity") == "critical"
            if should_notify:
                sent = await send_ntfy_alert(NTFY_URL, NTFY_TOPIC, normalized)
                normalized["notified"] = sent

            insert_alert(DB_PATH, normalized)
            inserted_count += 1
            if manual and len(new_alerts) < 20:
                new_alerts.append(
                    {
                        "severity": normalized.get("severity"),
                        "title": normalized.get("title"),
                        "source_name": normalized.get("source_name"),
                        "matched_tools": normalized.get("matched_tools", []),
                        "created_at": normalized.get("created_at"),
                    }
                )

        set_meta(DB_PATH, f"last_fetch_{key}", datetime.utcnow().isoformat())

    await maybe_send_high_digest()

    return {
        "status": "ok",
        "inserted": inserted_count,
        "new_alerts": new_alerts,
    }


async def maybe_send_high_digest() -> None:
    if not NTFY_URL or not NTFY_TOPIC:
        return

    today = datetime.utcnow().date().isoformat()
    last_digest = get_meta(DB_PATH, "last_digest_date")
    if last_digest == today:
        return

    since_iso = f"{today}T00:00:00"
    if last_digest:
        since_iso = f"{last_digest}T00:00:00"

    alerts = list_alerts_since(DB_PATH, "high", since_iso)
    if alerts:
        await send_ntfy_digest(NTFY_URL, NTFY_TOPIC, alerts)

    set_meta(DB_PATH, "last_digest_date", today)


async def collector_loop() -> None:
    while True:
        await collect_cycle()
        await asyncio.sleep(CRON_INTERVAL)


def main() -> None:
    uvicorn.run(app, host="0.0.0.0", port=WEB_PORT)


if __name__ == "__main__":
    main()
