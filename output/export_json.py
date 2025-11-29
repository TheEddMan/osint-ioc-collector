import json
import os
import sqlite3
from typing import Dict, Any, List

from database.db import get_recent_iocs


def export_latest_iocs_json(limit: int = 300,
                            path: str = "docs/data/latest_iocs.json") -> None:
    """Export latest IOCs to a simple JSON list for the static dashboard."""
    rows = get_recent_iocs(limit=limit)
    data: List[Dict[str, Any]] = []

    for row in rows:
        ioc_id, ioc_type, value, source, enrichment_json, first_seen = row
        data.append({
            "id": ioc_id,
            "type": ioc_type,
            "value": value,
            "source": source,
            "first_seen": first_seen,
        })

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[JSON] Wrote latest IOCs to {path}")


def export_counts_json(days: int = 7,
                       path: str = "docs/data/ioc_counts.json") -> None:
    """
    Export counts per day & type for the last N days.
    Structure:
    {
      "labels": ["2025-11-28", ...],
      "types": ["ip", "domain", ...],
      "series": {"ip": [..], "domain": [..], ...}
    }
    """
    conn = sqlite3.connect("osint.db")
    cur = conn.cursor()
    cur.execute("""
        SELECT DATE(first_seen), type, COUNT(*)
        FROM iocs
        WHERE first_seen >= datetime('now', ?)
        GROUP BY DATE(first_seen), type
        ORDER BY DATE(first_seen)
    """, (f"-{days} days",))
    rows = cur.fetchall()
    conn.close()

    data: Dict[str, Dict[str, int]] = {}
    for day, t, c in rows:
        data.setdefault(day, {})[t] = c

    labels = sorted(data.keys())
    all_types = set()
    for d in data.values():
        all_types.update(d.keys())
    types = sorted(all_types)

    series: Dict[str, List[int]] = {t: [] for t in types}
    for day in labels:
        day_data = data.get(day, {})
        for t in types:
            series[t].append(day_data.get(t, 0))

    payload = {
        "labels": labels,
        "types": types,
        "series": series,
    }

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"[JSON] Wrote counts to {path}")
