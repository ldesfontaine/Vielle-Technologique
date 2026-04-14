import json
import os
import re
import uuid
from typing import Dict, List

CUSTOM_TOOLS_PATH = os.path.join("config", "custom-tools.json")


def load_tools() -> List[Dict[str, object]]:
    tools: List[Dict[str, object]] = []

    watch_stack = os.environ.get("WATCH_STACK", "").strip()
    for name in [item.strip() for item in watch_stack.split(",") if item.strip()]:
        tools.append(
            {
                "id": f"auto-{name.lower()}",
                "name": name,
                "keywords": [name.lower()],
                "source": "auto",
                "version": None,
                "cpe": None,
            }
        )

    if os.path.exists(CUSTOM_TOOLS_PATH):
        with open(CUSTOM_TOOLS_PATH, "r", encoding="utf-8") as handle:
            custom = json.load(handle)
            for tool in custom:
                name = tool["name"]
                keywords = [kw.lower() for kw in tool.get("keywords", [])]
                if name.lower() not in keywords:
                    keywords.append(name.lower())
                tools.append(
                    {
                        "id": tool.get("id") or f"custom-{uuid.uuid4().hex}",
                        "name": name,
                        "keywords": keywords,
                        "source": "custom",
                        "version": tool.get("version"),
                        "cpe": tool.get("cpe"),
                    }
                )

    return tools


def add_custom_tool(name: str, keywords: List[str], version: str | None, cpe: str | None, source: str | None = "custom") -> Dict[str, object]:
    cleaned = [kw.lower() for kw in keywords]
    if name.lower() not in cleaned:
        cleaned.append(name.lower())

    resolved_source = source or "custom"
    tool = {
        "id": f"custom-{uuid.uuid4().hex}",
        "name": name,
        "keywords": cleaned,
        "version": version,
        "cpe": cpe,
        "source": resolved_source,
    }

    tools = []
    if os.path.exists(CUSTOM_TOOLS_PATH):
        with open(CUSTOM_TOOLS_PATH, "r", encoding="utf-8") as handle:
            tools = json.load(handle)

    tools.append(tool)
    os.makedirs(os.path.dirname(CUSTOM_TOOLS_PATH), exist_ok=True)
    with open(CUSTOM_TOOLS_PATH, "w", encoding="utf-8") as handle:
        json.dump(tools, handle, indent=2)

    return tool


def delete_custom_tool(tool_id: str) -> bool:
    if not os.path.exists(CUSTOM_TOOLS_PATH):
        return False

    with open(CUSTOM_TOOLS_PATH, "r", encoding="utf-8") as handle:
        tools = json.load(handle)

    filtered = [tool for tool in tools if tool.get("id") != tool_id]
    if len(filtered) == len(tools):
        return False

    with open(CUSTOM_TOOLS_PATH, "w", encoding="utf-8") as handle:
        json.dump(filtered, handle, indent=2)

    return True


def match_tools(text: str, tools: List[Dict[str, object]]) -> List[str]:
    text_lower = text.lower()
    matched: List[str] = []

    for tool in tools:
        keywords = tool.get("keywords", [])
        cpe = str(tool.get("cpe") or "").lower()
        version = str(tool.get("version") or "").lower()
        tool_name = str(tool.get("name") or "")

        matched_tool = False

        for keyword in keywords:
            if keyword and keyword in text_lower:
                matched_tool = True
                break

        if not matched_tool and cpe and cpe in text_lower:
            matched_tool = True

        if not matched_tool and version and tool_name.lower() in text_lower:
            if version in text_lower or f"v{version}" in text_lower:
                matched_tool = True

        if matched_tool:
            matched.append(tool_name)

    return matched


def extract_cve_ids(text: str) -> List[str]:
    return list({match.group(0).upper() for match in re.finditer(r"CVE-\d{4}-\d{4,7}", text)})
