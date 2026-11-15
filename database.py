"""SQLite Database module for SHADOW Wi-Fi (Part 3).

Maintains all persistent state for the SHADOW Wi-Fi analyzer:
- trusted_profiles: registered known AP configurations
- discovered_aps: live/historical scan records
- suspicious_events: alerts for rogue APs or security mismatches
- auth_results: Part 2 cryptographic challenge-response outcomes
- security_logs: unified audit log timeline

All modules write through the helper functions defined here to ensure
schema consistency across all three project parts.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Default database location: data/shadow_wifi.db
DEFAULT_DB_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "shadow_wifi.db"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db_connection(db_path: Optional[str | Path] = None) -> sqlite3.Connection:
    """Open and return a SQLite database connection with row factory enabled."""
    target_path = Path(db_path) if db_path else DEFAULT_DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str | Path] = None, seed_defaults: bool = True) -> None:
    """Initialize SQLite tables and indexes.

    Optionally seeds initial trusted profiles (e.g. College_WiFi) if the table
    is empty.
    """
    conn = get_db_connection(db_path)
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS trusted_profiles (
            ssid TEXT PRIMARY KEY,
            allowed_bssids TEXT NOT NULL, -- JSON array of BSSIDs in uppercase
            security TEXT NOT NULL,       -- e.g. WPA2, WPA3, Open
            pubkey_fingerprint TEXT,      -- SHA-256 fingerprint of Ed25519 public key
            owner TEXT,                   -- Description or department
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS discovered_aps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid TEXT NOT NULL,
            bssid TEXT NOT NULL,
            channel INTEGER,
            signal INTEGER,
            security TEXT,
            status TEXT,                  -- CANDIDATE_TRUSTED, SUSPICIOUS, SECURITY_MISMATCH, UNKNOWN
            scanned_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS suspicious_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ssid TEXT NOT NULL,
            bssid TEXT NOT NULL,
            event_type TEXT NOT NULL,     -- SUSPICIOUS_BSSID, SECURITY_MISMATCH, REPLAY_ATTACK, AUTH_FAILURE
            description TEXT NOT NULL,
            details TEXT                  -- JSON or textual context
        );

        CREATE TABLE IF NOT EXISTS auth_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ssid TEXT NOT NULL,
            bssid TEXT NOT NULL,
            auth_result TEXT NOT NULL,    -- SUCCESS, FAILED
            reason TEXT NOT NULL,
            has_session_key INTEGER NOT NULL DEFAULT 0,
            session_key_fingerprint TEXT  -- SHA-256 of session key (never raw key)
        );

        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,          -- INFO, WARNING, ERROR, SUCCESS
            component TEXT NOT NULL,      -- SCANNER, DETECTOR, AUTH, SESSION, SYSTEM
            message TEXT NOT NULL,
            details TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_discovered_aps_ts ON discovered_aps(scanned_at DESC);
        CREATE INDEX IF NOT EXISTS idx_discovered_aps_ssid ON discovered_aps(ssid);
        CREATE INDEX IF NOT EXISTS idx_suspicious_events_ts ON suspicious_events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_auth_results_ts ON auth_results(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_security_logs_ts ON security_logs(timestamp DESC);
        """)

        if seed_defaults:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM trusted_profiles")
            if cur.fetchone()[0] == 0:
                now = _now_iso()
                defaults = [
                    (
                        "College_WiFi",
                        json.dumps(["AA:BB:CC:11:22:33", "AA:BB:CC:11:22:34"]),
                        "WPA2",
                        "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
                        "Campus IT Admin",
                        now,
                    ),
                    (
                        "Home_Secure_WiFi",
                        json.dumps(["00:11:22:33:44:55"]),
                        "WPA2",
                        None,
                        "Lab Hotspot",
                        now,
                    ),
                ]
                cur.executemany(
                    """
                    INSERT INTO trusted_profiles 
                    (ssid, allowed_bssids, security, pubkey_fingerprint, owner, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    defaults,
                )
    conn.close()


# ---------------------------------------------------------------------------
# Trusted Profiles CRUD
# ---------------------------------------------------------------------------

def save_trusted_profile(
    ssid: str,
    allowed_bssids: List[str],
    security: str,
    pubkey_fingerprint: Optional[str] = None,
    owner: Optional[str] = None,
    db_path: Optional[str | Path] = None,
) -> None:
    """Add or update a trusted AP profile."""
    normalized_bssids = [b.strip().upper() for b in allowed_bssids if b.strip()]
    conn = get_db_connection(db_path)
    with conn:
        conn.execute(
            """
            INSERT INTO trusted_profiles (ssid, allowed_bssids, security, pubkey_fingerprint, owner, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ssid) DO UPDATE SET
                allowed_bssids = excluded.allowed_bssids,
                security = excluded.security,
                pubkey_fingerprint = excluded.pubkey_fingerprint,
                owner = excluded.owner
            """,
            (
                ssid.strip(),
                json.dumps(normalized_bssids),
                security.strip(),
                pubkey_fingerprint.strip() if pubkey_fingerprint else None,
                owner.strip() if owner else None,
                _now_iso(),
            ),
        )
    conn.close()


def get_trusted_profiles(db_path: Optional[str | Path] = None) -> Dict[str, Dict[str, Any]]:
    """Retrieve all trusted profiles as a dict mapping ssid -> profile dict.

    Output format matches the schema expected by detector.analyze_ap:
        {
            "ssid": str,
            "allowed_bssids": list[str],
            "security": str,
            "pubkey_fingerprint": str | None,
            "owner": str | None
        }
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT ssid, allowed_bssids, security, pubkey_fingerprint, owner FROM trusted_profiles")
        rows = cur.fetchall()
        profiles = {}
        for row in rows:
            try:
                bssids = json.loads(row["allowed_bssids"])
            except (ValueError, TypeError):
                bssids = [row["allowed_bssids"].upper()]
            profiles[row["ssid"]] = {
                "ssid": row["ssid"],
                "allowed_bssids": [b.upper() for b in bssids],
                "security": row["security"],
                "pubkey_fingerprint": row["pubkey_fingerprint"],
                "owner": row["owner"],
            }
        return profiles
    finally:
        conn.close()


def delete_trusted_profile(ssid: str, db_path: Optional[str | Path] = None) -> bool:
    """Delete a trusted profile by SSID."""
    conn = get_db_connection(db_path)
    with conn:
        cur = conn.execute("DELETE FROM trusted_profiles WHERE ssid = ?", (ssid,))
        deleted = cur.rowcount > 0
    conn.close()
    return deleted


# ---------------------------------------------------------------------------
# Scans and Suspicious Events
# ---------------------------------------------------------------------------

def save_scan_results(
    analyzed_aps: List[Dict[str, Any]],
    db_path: Optional[str | Path] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """Save a batch of analyzed AP scan results.

    Automatically triggers creation of suspicious_events records for APs
    classified as SUSPICIOUS or SECURITY_MISMATCH.
    """
    if not analyzed_aps:
        return

    should_close = False
    if conn is None:
        conn = get_db_connection(db_path)
        should_close = True

    now = _now_iso()
    try:
        with conn:
            for ap in analyzed_aps:
                ssid = ap.get("ssid", "")
                bssid = ap.get("bssid", "").upper()
                channel = ap.get("channel", 0)
                signal = ap.get("signal", 0)
                security = ap.get("security", "")
                status = ap.get("status", "UNKNOWN")
                scanned_at = ap.get("ts", now)

                conn.execute(
                    """
                    INSERT INTO discovered_aps (ssid, bssid, channel, signal, security, status, scanned_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ssid, bssid, channel, signal, security, status, scanned_at),
                )

                # Auto-flag suspicious scans
                if status == "SUSPICIOUS":
                    conn.execute(
                        """
                        INSERT INTO suspicious_events (timestamp, ssid, bssid, event_type, description, details)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scanned_at,
                            ssid,
                            bssid,
                            "SUSPICIOUS_BSSID",
                            f"Duplicate SSID detected with unregistered BSSID: {bssid}",
                            json.dumps({"signal": signal, "security": security, "channel": channel}),
                        ),
                    )
                    log_event(
                        "WARNING",
                        "DETECTOR",
                        f"Rogue AP indicator: duplicate SSID '{ssid}' with unknown BSSID {bssid}",
                        db_path=db_path,
                        conn=conn,
                    )
                elif status == "SECURITY_MISMATCH":
                    conn.execute(
                        """
                        INSERT INTO suspicious_events (timestamp, ssid, bssid, event_type, description, details)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scanned_at,
                            ssid,
                            bssid,
                            "SECURITY_MISMATCH",
                            f"Security configuration mismatch for SSID '{ssid}' (scanned: {security})",
                            json.dumps({"signal": signal, "security": security, "channel": channel}),
                        ),
                    )
                    log_event(
                        "WARNING",
                        "DETECTOR",
                        f"Security mismatch on '{ssid}': observed {security}",
                        db_path=db_path,
                        conn=conn,
                    )
    finally:
        if should_close:
            conn.close()


def save_suspicious_event(
    ssid: str,
    bssid: str,
    event_type: str,
    description: str,
    details: Optional[Any] = None,
    db_path: Optional[str | Path] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """Manually record a suspicious security event."""
    should_close = False
    if conn is None:
        conn = get_db_connection(db_path)
        should_close = True

    try:
        with conn:
            conn.execute(
                """
                INSERT INTO suspicious_events (timestamp, ssid, bssid, event_type, description, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    _now_iso(),
                    ssid,
                    bssid.upper(),
                    event_type,
                    description,
                    json.dumps(details) if isinstance(details, (dict, list)) else str(details or ""),
                ),
            )
    finally:
        if should_close:
            conn.close()


# ---------------------------------------------------------------------------
# Cryptographic Authentication Results
# ---------------------------------------------------------------------------

def save_auth_result(
    ap: Dict[str, Any],
    auth_result: str,
    reason: str,
    session_key: Optional[bytes] = None,
    db_path: Optional[str | Path] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """Record a cryptographic challenge-response outcome from Part 2.

    session_key is fingerprinted (SHA-256) for audit purposes; raw secret keys
    are never stored in plaintext on disk.
    """
    import hashlib

    ssid = ap.get("ssid", "")
    bssid = ap.get("bssid", "").upper()
    has_key = 1 if session_key else 0
    key_fingerprint = hashlib.sha256(session_key).hexdigest() if session_key else None

    should_close = False
    if conn is None:
        conn = get_db_connection(db_path)
        should_close = True

    now = _now_iso()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO auth_results (timestamp, ssid, bssid, auth_result, reason, has_session_key, session_key_fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (now, ssid, bssid, auth_result.upper(), reason, has_key, key_fingerprint),
            )

            level = "SUCCESS" if auth_result.upper() == "SUCCESS" else "ERROR"
            log_event(
                level,
                "AUTHENTICATION",
                f"Auth {auth_result} for {ssid} [{bssid}]: {reason}",
                db_path=db_path,
                conn=conn,
            )
    finally:
        if should_close:
            conn.close()


# ---------------------------------------------------------------------------
# Unified Security Event Log
# ---------------------------------------------------------------------------

def log_event(
    level: str,
    component: str,
    message: str,
    details: Optional[Any] = None,
    db_path: Optional[str | Path] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """Insert a record into the unified security timeline."""
    should_close = False
    if conn is None:
        conn = get_db_connection(db_path)
        should_close = True

    try:
        with conn:
            conn.execute(
                """
                INSERT INTO security_logs (timestamp, level, component, message, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    _now_iso(),
                    level.upper(),
                    component.upper(),
                    message,
                    json.dumps(details) if isinstance(details, (dict, list)) else (str(details) if details else None),
                ),
            )
    finally:
        if should_close:
            conn.close()


def log_everything(
    analyzed_aps: List[Dict[str, Any]],
    auth_results: List[Dict[str, Any]],
    db_path: Optional[str | Path] = None,
) -> None:
    """Bulk helper to log an entire integration run in one step."""
    conn = get_db_connection(db_path)
    try:
        save_scan_results(analyzed_aps, db_path=db_path, conn=conn)
        for res in auth_results:
            ap = res.get("ap", {})
            auth_res = res.get("auth_result", "FAILED")
            reason = res.get("reason", "")
            session_key = res.get("session_key")
            save_auth_result(ap, auth_res, reason, session_key=session_key, db_path=db_path, conn=conn)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Query & Dashboard Reporting Helpers
# ---------------------------------------------------------------------------

def get_recent_scans(limit: int = 50, db_path: Optional[str | Path] = None) -> List[Dict[str, Any]]:
    """Fetch the most recent AP scan records."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, ssid, bssid, channel, signal, security, status, scanned_at
            FROM discovered_aps
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_suspicious_events(limit: int = 50, db_path: Optional[str | Path] = None) -> List[Dict[str, Any]]:
    """Fetch recent rogue AP alerts and security mismatches."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, timestamp, ssid, bssid, event_type, description, details
            FROM suspicious_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_auth_results(limit: int = 50, db_path: Optional[str | Path] = None) -> List[Dict[str, Any]]:
    """Fetch recent cryptographic authentication outcomes."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, timestamp, ssid, bssid, auth_result, reason, has_session_key, session_key_fingerprint
            FROM auth_results
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_security_logs(limit: int = 100, db_path: Optional[str | Path] = None) -> List[Dict[str, Any]]:
    """Fetch recent entries from the unified audit log timeline."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, timestamp, level, component, message, details
            FROM security_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_summary_metrics(db_path: Optional[str | Path] = None) -> Dict[str, int]:
    """Calculate the 4 core KPI metrics for the Streamlit dashboard:
    - APs discovered (total or unique recent)
    - Suspicious APs
    - Candidate trusted APs
    - Authentication failures
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM discovered_aps")
        total_discovered = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM discovered_aps WHERE status = 'SUSPICIOUS'")
        suspicious_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM discovered_aps WHERE status = 'CANDIDATE_TRUSTED'")
        candidate_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM auth_results WHERE auth_result = 'FAILED'")
        auth_failures = cur.fetchone()[0]

        return {
            "total_discovered": total_discovered,
            "suspicious_aps": suspicious_count,
            "candidate_trusted": candidate_count,
            "auth_failures": auth_failures,
        }
    finally:
        conn.close()
