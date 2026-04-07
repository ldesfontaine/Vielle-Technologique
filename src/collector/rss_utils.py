import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, List


def parse_datetime(value: str) -> datetime:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.utcnow()

    if parsed.tzinfo:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def parse_rss(xml_text: str) -> List[Dict[str, str]]:
    root = ET.fromstring(xml_text)
    entries: List[Dict[str, str]] = []

    if root.tag.endswith("rss"):
        channel = root.find("channel")
        if channel is None:
            return entries
        for item in channel.findall("item"):
            entries.append(
                {
                    "title": (item.findtext("title") or "").strip(),
                    "link": (item.findtext("link") or "").strip(),
                    "summary": (item.findtext("description") or "").strip(),
                    "published": (item.findtext("pubDate") or "").strip(),
                }
            )
    else:
        namespace = "{http://www.w3.org/2005/Atom}"
        for entry in root.findall(f"{namespace}entry"):
            link_el = entry.find(f"{namespace}link")
            link = link_el.attrib.get("href", "") if link_el is not None else ""
            entries.append(
                {
                    "title": (entry.findtext(f"{namespace}title") or "").strip(),
                    "link": link.strip(),
                    "summary": (entry.findtext(f"{namespace}summary") or "").strip(),
                    "published": (entry.findtext(f"{namespace}updated") or "").strip(),
                }
            )

    return entries
