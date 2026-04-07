from datetime import datetime, timedelta
from typing import Dict, List, Optional

import httpx

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_cisa_kev(last_fetch: Optional[str]) -> List[Dict[str, object]]:
    since = (
        datetime.fromisoformat(last_fetch)
        if last_fetch
        else datetime.utcnow() - timedelta(days=2)
    )

    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(CISA_KEV_URL)
        response.raise_for_status()
        data = response.json()

    alerts: List[Dict[str, object]] = []
    for item in data.get("vulnerabilities", []):
        date_added = item.get("dateAdded") or ""
        try:
            published = datetime.fromisoformat(date_added)
        except ValueError:
            published = datetime.utcnow()

        if published < since:
            continue

        alerts.append(
            {
                "source_id": "cisa-kev",
                "source_name": "CISA KEV",
                "title": f"{item.get('cveID', '')} - {item.get('shortDescription', '')}",
                "description": item.get("shortDescription", ""),
                "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "cve_id": item.get("cveID"),
                "severity": "high",
            }
        )

    return alerts
