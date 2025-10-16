
import sqlite3, os, threading, time
from typing import Optional, Dict, Any, List, Tuple

DB_FILE = os.path.join(os.path.dirname(__file__), "pihole_manager.sqlite3")
_lock = threading.RLock()

def _conn():
    c = sqlite3.connect(DB_FILE, check_same_thread=False)
    c.execute("PRAGMA journal_mode = WAL;")
    c.execute("PRAGMA foreign_keys = ON;")
    return c

def init_db():
    with _lock, _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS domains(
          id INTEGER PRIMARY KEY,
          domain TEXT UNIQUE NOT NULL,
          first_seen INTEGER,
          last_seen INTEGER
        );
        CREATE TABLE IF NOT EXISTS annotations(
          id INTEGER PRIMARY KEY,
          domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
          source TEXT NOT NULL,
          category TEXT,
          policy TEXT,
          short TEXT,
          details TEXT,
          provider TEXT,
          created_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_ann_domain_created ON annotations(domain_id, created_at DESC);
        CREATE TABLE IF NOT EXISTS actions(
          id INTEGER PRIMARY KEY,
          domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
          action TEXT NOT NULL,
          list_kind TEXT NOT NULL, -- allow|deny
          comment TEXT,
          by_user INTEGER DEFAULT 0,
          by_auto INTEGER DEFAULT 0,
          created_at INTEGER
        );
        """)

def upsert_domain(domain: str, ts: Optional[int]=None) -> int:
    ts = ts or int(time.time())
    with _lock, _conn() as c:
        c.execute("INSERT INTO domains(domain, first_seen, last_seen) VALUES(?,?,?) ON CONFLICT(domain) DO UPDATE SET last_seen=excluded.last_seen",
                  (domain, ts, ts))
        c.execute("SELECT id FROM domains WHERE domain=?", (domain,))
        return c.fetchone()[0]

def get_annotation(domain: str) -> Optional[Dict[str, Any]]:
    with _lock, _conn() as c:
        c.execute("""
            SELECT a.category, a.policy, a.short, a.details, a.provider, a.created_at
            FROM annotations a
            JOIN domains d ON d.id = a.domain_id
            WHERE d.domain = ?
            ORDER BY a.created_at DESC LIMIT 1
        """, (domain,))
        row = c.fetchone()
        if not row:
            return None
        keys = ["category","policy","short","details","provider","created_at"]
        return dict(zip(keys, row))

def save_annotation(domain: str, source: str, category: str, policy: str, short: str, details: str, provider: str, ts: Optional[int]=None) -> None:
    ts = ts or int(time.time())
    did = upsert_domain(domain, ts)
    with _lock, _conn() as c:
        c.execute("""
            INSERT INTO annotations(domain_id, source, category, policy, short, details, provider, created_at)
            VALUES(?,?,?,?,?,?,?,?)
        """, (did, source, category, policy, short, details, provider, ts))

def log_action(domain: str, action: str, list_kind: str, comment: str, by_user: bool, by_auto: bool, ts: Optional[int]=None) -> None:
    ts = ts or int(time.time())
    did = upsert_domain(domain, ts)
    with _lock, _conn() as c:
        c.execute("""
            INSERT INTO actions(domain_id, action, list_kind, comment, by_user, by_auto, created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (did, action, list_kind, comment, 1 if by_user else 0, 1 if by_auto else 0, ts))
