import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.matcher import match_tools, extract_cve_ids


def test_match_tools_by_keyword():
    tools = [
        {"name": "traefik", "keywords": ["traefik", "traefik-proxy"], "cpe": None, "version": None},
        {"name": "nginx", "keywords": ["nginx"], "cpe": None, "version": None},
    ]
    text = "Vulnerability in traefik reverse proxy allows RCE"
    matched = match_tools(text, tools)
    assert matched == ["traefik"]


def test_match_tools_no_match():
    tools = [
        {"name": "docker", "keywords": ["docker", "containerd"], "cpe": None, "version": None},
    ]
    text = "Apache HTTP Server vulnerability CVE-2024-1234"
    matched = match_tools(text, tools)
    assert matched == []


def test_match_tools_multiple():
    tools = [
        {"name": "linux", "keywords": ["linux", "kernel"], "cpe": None, "version": None},
        {"name": "docker", "keywords": ["docker", "containerd"], "cpe": None, "version": None},
    ]
    text = "Linux kernel vulnerability affects Docker containers"
    matched = match_tools(text, tools)
    assert "linux" in matched
    assert "docker" in matched


def test_match_tools_case_insensitive():
    tools = [
        {"name": "Vaultwarden", "keywords": ["vaultwarden"], "cpe": None, "version": None},
    ]
    text = "VAULTWARDEN password manager flaw discovered"
    matched = match_tools(text, tools)
    assert matched == ["Vaultwarden"]


def test_extract_cve_ids_single():
    text = "CVE-2024-12345 affects multiple systems"
    cves = extract_cve_ids(text)
    assert cves == ["CVE-2024-12345"]


def test_extract_cve_ids_multiple():
    text = "CVE-2024-1234 and CVE-2023-56789 are critical"
    cves = extract_cve_ids(text)
    assert set(cves) == {"CVE-2024-1234", "CVE-2023-56789"}


def test_extract_cve_ids_none():
    text = "No vulnerabilities found in this text"
    cves = extract_cve_ids(text)
    assert cves == []


def test_extract_cve_ids_dedup():
    text = "CVE-2024-1234 is mentioned twice: CVE-2024-1234"
    cves = extract_cve_ids(text)
    assert cves == ["CVE-2024-1234"]
