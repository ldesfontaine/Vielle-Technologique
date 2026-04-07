from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os

import httpx

GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"


async def fetch_github_advisories(last_fetch: Optional[str]) -> List[Dict[str, object]]:
    since = (
        datetime.fromisoformat(last_fetch)
        if last_fetch
        else datetime.utcnow() - timedelta(days=1)
    )

    params = {"per_page": 100, "since": since.isoformat()}
    headers = {"Accept": "application/vnd.github+json"}

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(GITHUB_ADVISORIES_URL, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()

    alerts: List[Dict[str, object]] = []
    for item in data:
        severity = (item.get("severity") or "medium").lower()
        alerts.append(
            {
                "source_id": "github-advisories",
                "source_name": "GitHub Advisories",
                "title": item.get("summary") or item.get("ghsa_id") or "GitHub Advisory",
                "description": item.get("description") or "",
                "link": item.get("html_url") or "",
                "cve_id": item.get("cve_id"),
                "severity": severity,
            }
        )

    return alerts
