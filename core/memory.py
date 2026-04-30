"""
core/memory.py — SQLite persistence for scan history and chat memory.
"""

import sqlite3
import json
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

import config
from models.schema import ScanResult, ChatMessage

logger = logging.getLogger(__name__)


def get_connection() -> sqlite3.Connection:
    """Get a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create database tables if they don't exist."""
    conn = get_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id     TEXT PRIMARY KEY,
                domain      TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                result_json TEXT,
                created_at  TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
            CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);

            CREATE TABLE IF NOT EXISTS chat_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL,
                role        TEXT NOT NULL,
                content     TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_chat_scan_id ON chat_history(scan_id);
        """)
        conn.commit()
        logger.info("[memory] Database initialized")
    finally:
        conn.close()


# ─── Scan Operations ─────────────────────────────────────────────────────────

def save_scan(scan: ScanResult) -> None:
    """Insert or update a scan record."""
    conn = get_connection()
    try:
        result_json = scan.model_dump_json()
        conn.execute("""
            INSERT INTO scans (scan_id, domain, timestamp, status, result_json)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                status = excluded.status,
                result_json = excluded.result_json
        """, (scan.scan_id, scan.domain, scan.timestamp, scan.status, result_json))
        conn.commit()
    except Exception as e:
        logger.error(f"[memory] Failed to save scan {scan.scan_id}: {e}")
        conn.rollback()
    finally:
        conn.close()


def get_scan(scan_id: str) -> Optional[ScanResult]:
    """Load a scan by ID."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if row and row["result_json"]:
            return ScanResult.model_validate_json(row["result_json"])
        return None
    except Exception as e:
        logger.error(f"[memory] Failed to load scan {scan_id}: {e}")
        return None
    finally:
        conn.close()


def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Return a list of scan summaries (no full result_json)."""
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT scan_id, domain, timestamp, status
            FROM scans
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"[memory] Failed to list scans: {e}")
        return []
    finally:
        conn.close()


def update_scan_status(scan_id: str, status: str, result: Optional[ScanResult] = None) -> None:
    """Update just the status (and optionally full result) of a scan."""
    conn = get_connection()
    try:
        if result:
            conn.execute("""
                UPDATE scans SET status = ?, result_json = ? WHERE scan_id = ?
            """, (status, result.model_dump_json(), scan_id))
        else:
            conn.execute(
                "UPDATE scans SET status = ? WHERE scan_id = ?", (status, scan_id)
            )
        conn.commit()
    except Exception as e:
        logger.error(f"[memory] Failed to update scan {scan_id}: {e}")
        conn.rollback()
    finally:
        conn.close()


def delete_scan(scan_id: str) -> bool:
    """Delete a scan and its chat history."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM chat_history WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"[memory] Failed to delete scan {scan_id}: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


# ─── Chat History Operations ─────────────────────────────────────────────────

def save_message(scan_id: str, message: ChatMessage) -> None:
    """Persist a chat message."""
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO chat_history (scan_id, role, content, timestamp)
            VALUES (?, ?, ?, ?)
        """, (scan_id, message.role, message.content, message.timestamp))
        conn.commit()
    except Exception as e:
        logger.error(f"[memory] Failed to save message for scan {scan_id}: {e}")
        conn.rollback()
    finally:
        conn.close()


def get_chat_history(scan_id: str, limit: int = 20) -> List[ChatMessage]:
    """Load recent chat history for a scan."""
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT role, content, timestamp
            FROM chat_history
            WHERE scan_id = ?
            ORDER BY id DESC
            LIMIT ?
        """, (scan_id, limit)).fetchall()
        # Return in chronological order
        return [
            ChatMessage(role=r["role"], content=r["content"], timestamp=r["timestamp"])
            for r in reversed(rows)
        ]
    except Exception as e:
        logger.error(f"[memory] Failed to load chat history for {scan_id}: {e}")
        return []
    finally:
        conn.close()


def clear_chat_history(scan_id: str) -> None:
    """Clear chat history for a scan."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM chat_history WHERE scan_id = ?", (scan_id,))
        conn.commit()
    finally:
        conn.close()
