import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional


def ensure_db_path(db_path: str) -> None:
    directory = os.path.dirname(db_path)
    if directory:
        os.makedirs(directory, exist_ok=True)


def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    ensure_db_path(db_path)
    with get_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                link TEXT NOT NULL,
                cve_id TEXT,
                cvss_score REAL,
                severity TEXT NOT NULL,
                matched_tools TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                notified INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_cve ON alerts(cve_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_link ON alerts(link)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )


def get_meta(db_path: str, key: str) -> Optional[str]:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None


def set_meta(db_path: str, key: str, value: str) -> None:
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def alert_exists(db_path: str, cve_id: Optional[str], link: str) -> bool:
    with get_connection(db_path) as conn:
        if cve_id:
            row = conn.execute("SELECT 1 FROM alerts WHERE cve_id = ? LIMIT 1", (cve_id,)).fetchone()
            if row:
                return True
        row = conn.execute("SELECT 1 FROM alerts WHERE link = ? LIMIT 1", (link,)).fetchone()
        return row is not None


def insert_alert(db_path: str, alert: Dict[str, Any]) -> int:
    now = datetime.utcnow().isoformat()
    created_at = str(alert.get("created_at") or now)
    matched_tools = json.dumps(alert.get("matched_tools", []))

    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO alerts (
                source_id, source_name, title, description, link,
                cve_id, cvss_score, severity, matched_tools, status,
                created_at, updated_at, notified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert["source_id"],
                alert["source_name"],
                alert["title"],
                alert.get("description"),
                alert["link"],
                alert.get("cve_id"),
                alert.get("cvss_score"),
                alert["severity"],
                matched_tools,
                alert.get("status", "new"),
                created_at,
                now,
                1 if alert.get("notified", False) else 0,
            ),
        )
        return int(cursor.lastrowid)


def list_alerts(
    db_path: str,
    severity: Optional[List[str]] = None,
    tool: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    query = "SELECT * FROM alerts"
    clauses: List[str] = []
    params: List[Any] = []

    if severity:
        placeholders = ",".join("?" for _ in severity)
        clauses.append(f"severity IN ({placeholders})")
        params.extend(severity)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if tool:
        clauses.append("matched_tools LIKE ?")
        params.append(f"%\"{tool}\"%")

    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_connection(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [row_to_alert(row) for row in rows]


def get_alert(db_path: str, alert_id: int) -> Optional[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return row_to_alert(row) if row else None


def update_alert_status(db_path: str, alert_id: int, status: str) -> bool:
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
            (status, datetime.utcnow().isoformat(), alert_id),
        )
        return cursor.rowcount > 0


def get_stats(db_path: str) -> Dict[str, Any]:
    with get_connection(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()["count"]
        by_severity = conn.execute(
            "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
        ).fetchall()
        by_source = conn.execute(
            "SELECT source_name, COUNT(*) AS count FROM alerts GROUP BY source_name"
        ).fetchall()

    return {
        "total": total,
        "by_severity": {row["severity"]: row["count"] for row in by_severity},
        "by_source": {row["source_name"]: row["count"] for row in by_source},
    }


def list_alerts_since(db_path: str, severity: str, since_iso: str) -> List[Dict[str, Any]]:
    query = (
        "SELECT * FROM alerts WHERE severity = ? AND created_at >= ? ORDER BY created_at DESC"
    )
    with get_connection(db_path) as conn:
        rows = conn.execute(query, (severity, since_iso)).fetchall()
        return [row_to_alert(row) for row in rows]


def row_to_alert(row: Optional[sqlite3.Row]) -> Dict[str, Any]:
    if row is None:
        return {}
    return {
        "id": row["id"],
        "source_id": row["source_id"],
        "source_name": row["source_name"],
        "title": row["title"],
        "description": row["description"],
        "link": row["link"],
        "cve_id": row["cve_id"],
        "cvss_score": row["cvss_score"],
        "severity": row["severity"],
        "matched_tools": json.loads(row["matched_tools"] or "[]"),
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "notified": bool(row["notified"]),
    }
