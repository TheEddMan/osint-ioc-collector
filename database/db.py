import sqlite3
from contextlib import contextmanager
from typing import Optional, Dict, Any


DB_PATH = "osint.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        source TEXT NOT NULL,
        enrichment TEXT,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cur.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_unique
    ON iocs(type, value, source);
    """)
    conn.commit()
    conn.close()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


def store_ioc(ioc_type: str, value: str, source: str,
              enrichment: Optional[Dict[str, Any]] = None):
    import json
    enrichment_json = json.dumps(enrichment or {})
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute("""
            INSERT OR IGNORE INTO iocs (type, value, source, enrichment)
            VALUES (?, ?, ?, ?)
            """, (ioc_type, value, source, enrichment_json))
            conn.commit()
        except Exception as e:
            print(f"[DB] Error storing IOC {value}: {e}")


def get_recent_iocs(limit: int = 50):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
        SELECT id, type, value, source, enrichment, first_seen
        FROM iocs
        ORDER BY first_seen DESC
        LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
    return rows
