import httpx
from typing import Dict, List


def build_ntfy_message(alert: Dict[str, object]) -> str:
    title = str(alert.get("title", "Alerte"))
    link = str(alert.get("link", ""))
    severity = str(alert.get("severity", ""))
    cve = str(alert.get("cve_id", ""))
    source = str(alert.get("source_name", ""))
    tools = alert.get("matched_tools", [])
    collected_at = str(alert.get("created_at", ""))

    parts = [f"[{severity.upper()}] {title}"]
    if source:
        parts.append(f"Source: {source}")
    if cve:
        parts.append(f"CVE: {cve}")
    if tools:
        parts.append("Stack: " + ", ".join(str(tool) for tool in tools))
    if collected_at:
        parts.append(f"Collected: {collected_at}Z")
    if link:
        parts.append(link)
    return "\n".join(parts)


async def send_ntfy_alert(ntfy_url: str, topic: str, alert: Dict[str, object], *, token: str = "") -> bool:
    if not ntfy_url or not topic:
        return False

    message = build_ntfy_message(alert)
    url = f"{ntfy_url.rstrip('/')}/{topic}"
    headers: Dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(url, content=message.encode("utf-8"), headers=headers)
        return response.status_code >= 200 and response.status_code < 300


def build_digest_message(alerts: List[Dict[str, object]]) -> str:
    lines = [f"Digest high ({len(alerts)} alertes)"]
    for alert in alerts[:20]:
        title = str(alert.get("title", ""))
        source = str(alert.get("source_name", ""))
        tools = alert.get("matched_tools", [])
        tools_text = ", ".join(str(tool) for tool in tools)
        lines.append(f"- {title} [{source}] ({tools_text})")
    if len(alerts) > 20:
        lines.append(f"... +{len(alerts) - 20} autres")
    return "\n".join(lines)


async def send_ntfy_digest(ntfy_url: str, topic: str, alerts: List[Dict[str, object]], *, token: str = "") -> bool:
    if not ntfy_url or not topic:
        return False

    message = build_digest_message(alerts)
    url = f"{ntfy_url.rstrip('/')}/{topic}"
    headers: Dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(url, content=message.encode("utf-8"), headers=headers)
        return response.status_code >= 200 and response.status_code < 300
