from datetime import datetime, timedelta
from typing import Dict, List, Optional

import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def pick_cvss_score(metrics: Dict[str, object]) -> Optional[float]:
    if not metrics:
        return None

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            metric = entries[0]
            data = metric.get("cvssData") if isinstance(metric, dict) else None
            if isinstance(data, dict) and data.get("baseScore") is not None:
                return float(data["baseScore"])
    return None


async def fetch_nvd(last_fetch: Optional[str]) -> List[Dict[str, object]]:
    start = (
        datetime.fromisoformat(last_fetch)
        if last_fetch
        else datetime.utcnow() - timedelta(days=1)
    )
    end = datetime.utcnow()

    params = {
        "lastModStartDate": start.replace(microsecond=0).isoformat() + "Z",
        "lastModEndDate": end.replace(microsecond=0).isoformat() + "Z",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(NVD_API_URL, params=params)
        response.raise_for_status()
        data = response.json()

    alerts: List[Dict[str, object]] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        score = pick_cvss_score(cve.get("metrics", {}))

        alerts.append(
            {
                "source_id": "nvd",
                "source_name": "NVD",
                "title": cve_id or "NVD CVE",
                "description": description,
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
                "cve_id": cve_id,
                "cvss_score": score,
            }
        )

    return alerts
