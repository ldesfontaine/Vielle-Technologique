from datetime import datetime, timedelta
from typing import Dict, List, Optional

import httpx

from .rss_utils import parse_datetime, parse_rss

CERTFR_RSS_URL = "https://www.cert.ssi.gouv.fr/feed/"


async def fetch_certfr(last_fetch: Optional[str]) -> List[Dict[str, object]]:
    since = (
        datetime.fromisoformat(last_fetch)
        if last_fetch
        else datetime.utcnow() - timedelta(days=1)
    )

    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(CERTFR_RSS_URL)
        response.raise_for_status()
        entries = parse_rss(response.text)

    alerts: List[Dict[str, object]] = []
    for entry in entries:
        published = parse_datetime(entry.get("published", ""))
        if published < since:
            continue

        alerts.append(
            {
                "source_id": "certfr",
                "source_name": "CERT-FR",
                "title": entry.get("title", ""),
                "description": entry.get("summary", ""),
                "link": entry.get("link", ""),
                "severity": "medium",
            }
        )

    return alerts
