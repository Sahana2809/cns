"""Unit tests for database.py (Part 3 SQLite layer).

This was the largest module in the project with no dedicated tests - every
test here runs against a throwaway temp-file database (via db_path) so it
never touches the real data/shadow_wifi.db used by the live demo.
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import database


def make_temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def test_init_db_seeds_default_profiles():
    db_path = make_temp_db()
    try:
        database.init_db(db_path=db_path, seed_defaults=True)
        profiles = database.get_trusted_profiles(db_path=db_path)
        assert "College_WiFi" in profiles
        assert profiles["College_WiFi"]["allowed_bssids"] == ["AA:BB:CC:11:22:33", "AA:BB:CC:11:22:34"]
        assert profiles["College_WiFi"]["pubkey_fingerprint"] is None
    finally:
        os.remove(db_path)


def test_init_db_without_seeding_is_empty():
    db_path = make_temp_db()
    try:
        database.init_db(db_path=db_path, seed_defaults=False)
        assert database.get_trusted_profiles(db_path=db_path) == {}
    finally:
        os.remove(db_path)


def test_init_db_does_not_reseed_on_second_call():
    """Re-running init_db (e.g. on every app.py load) must not clobber
    profiles a user has already registered or updated."""
    db_path = make_temp_db()
    try:
        database.init_db(db_path=db_path, seed_defaults=True)
        database.save_trusted_profile(
            ssid="College_WiFi",
            allowed_bssids=["11:11:11:11:11:11"],
            security="WPA3",
            db_path=db_path,
        )
        database.init_db(db_path=db_path, seed_defaults=True)
        profiles = database.get_trusted_profiles(db_path=db_path)
        assert profiles["College_WiFi"]["allowed_bssids"] == ["11:11:11:11:11:11"]
        assert profiles["College_WiFi"]["security"] == "WPA3"
    finally:
        os.remove(db_path)


def test_save_trusted_profile_upserts_and_normalizes_bssids():
    db_path = make_temp_db()
    try:
        database.init_db(db_path=db_path, seed_defaults=False)
        database.save_trusted_profile(
            ssid="Lab_WiFi",
            allowed_bssids=["aa:bb:cc:dd:ee:ff", " "],
            security="WPA2",
            owner="Lab",
            db_path=db_path,
        )
        profiles = database.get_trusted_profiles(db_path=db_path)
        assert profiles["Lab_WiFi"]["allowed_bssids"] == ["AA:BB:CC:DD:EE:FF"]

        # Upsert: saving again with the same SSID updates in place, not duplicates
        database.save_trusted_profile(
            ssid="Lab_WiFi",
            allowed_bssids=["11:22:33:44:55:66"],
            security="WPA3",
            db_path=db_path,
        )
        profiles = database.get_trusted_profiles(db_path=db_path)
        assert len(profiles) == 1
        assert profiles["Lab_WiFi"]["security"] == "WPA3"
        assert profiles["Lab_WiFi"]["allowed_bssids"] == ["11:22:33:44:55:66"]
    finally:
        os.remove(db_path)


def test_delete_trusted_profile():
    db_path = make_temp_db()
    try:
        database.init_db(db_path=db_path, seed_defaults=True)
        assert database.delete_trusted_profile("College_WiFi", db_path=db_path) is True
        assert "College_WiFi" not in database.get_trusted_profiles(db_path=db_path)
        assert database.delete_trusted_profile("College_WiFi", db_path=db_path) is False
    finally:
        os.remove(db_path)


def test_save_scan_results_flags_suspicious_and_security_mismatch():
    db_path = make_temp_db()
    try:
        database.init_db(db_path=db_path, seed_defaults=False)
        analyzed = [
            {"ssid": "A", "bssid": "aa:aa:aa:aa:aa:aa", "channel": 1, "signal": 50, "security": "WPA2", "status": "CANDIDATE_TRUSTED", "ts": "t1"},
            {"ssid": "A", "bssid": "bb:bb:bb:bb:bb:bb", "channel": 1, "signal": 50, "security": "WPA2", "status": "SUSPICIOUS", "ts": "t2"},
            {"ssid": "A", "bssid": "aa:aa:aa:aa:aa:aa", "channel": 1, "signal": 50, "security": "Open", "status": "SECURITY_MISMATCH", "ts": "t3"},
            {"ssid": "B", "bssid": "cc:cc:cc:cc:cc:cc", "channel": 1, "signal": 50, "security": "Open", "status": "UNKNOWN", "ts": "t4"},
        ]
        database.save_scan_results(analyzed, db_path=db_path)

        scans = database.get_recent_scans(limit=10, db_path=db_path)
        assert len(scans) == 4
        # BSSIDs are stored uppercased regardless of input case
        assert all(s["bssid"] == s["bssid"].upper() for s in scans)

        events = database.get_suspicious_events(limit=10, db_path=db_path)
        event_types = sorted(e["event_type"] for e in events)
        assert event_types == ["SECURITY_MISMATCH", "SUSPICIOUS_BSSID"]

        logs = database.get_security_logs(limit=10, db_path=db_path)
        assert any(log["component"] == "DETECTOR" for log in logs)


    finally:
        os.remove(db_path)


def test_save_scan_results_with_empty_list_is_a_noop():
    db_path = make_temp_db()
    try:
        database.init_db(db_path=db_path, seed_defaults=False)
        database.save_scan_results([], db_path=db_path)
        assert database.get_recent_scans(db_path=db_path) == []
    finally:
        os.remove(db_path)


def test_save_auth_result_fingerprints_session_key_not_raw_bytes():
    db_path = make_temp_db()
    try:
        database.init_db(db_path=db_path, seed_defaults=False)
        session_key = b"\x01" * 32
        database.save_auth_result(
            {"ssid": "A", "bssid": "aa:aa:aa:aa:aa:aa"},
            "SUCCESS",
            "AP identity verified",
            session_key=session_key,
            db_path=db_path,
        )
        results = database.get_auth_results(db_path=db_path)
        assert len(results) == 1
        assert results[0]["has_session_key"] == 1
        assert results[0]["session_key_fingerprint"] is not None
        assert session_key.hex() not in str(results[0])
    finally:
        os.remove(db_path)


def test_save_auth_result_without_session_key():
    db_path = make_temp_db()
    try:
        database.init_db(db_path=db_path, seed_defaults=False)
        database.save_auth_result(
            {"ssid": "A", "bssid": "aa:aa:aa:aa:aa:aa"},
            "FAILED",
            "Invalid digital signature",
            session_key=None,
            db_path=db_path,
        )
        results = database.get_auth_results(db_path=db_path)
        assert results[0]["has_session_key"] == 0
        assert results[0]["session_key_fingerprint"] is None
    finally:
        os.remove(db_path)


def test_get_summary_metrics():
    db_path = make_temp_db()
    try:
        database.init_db(db_path=db_path, seed_defaults=False)
        analyzed = [
            {"ssid": "A", "bssid": "aa:aa:aa:aa:aa:aa", "status": "CANDIDATE_TRUSTED", "channel": 1, "signal": 1, "security": "WPA2", "ts": "t"},
            {"ssid": "A", "bssid": "bb:bb:bb:bb:bb:bb", "status": "SUSPICIOUS", "channel": 1, "signal": 1, "security": "WPA2", "ts": "t"},
        ]
        database.save_scan_results(analyzed, db_path=db_path)
        database.save_auth_result({"ssid": "A", "bssid": "aa:aa:aa:aa:aa:aa"}, "FAILED", "no key", db_path=db_path)

        metrics = database.get_summary_metrics(db_path=db_path)
        assert metrics == {
            "total_discovered": 2,
            "suspicious_aps": 1,
            "candidate_trusted": 1,
            "auth_failures": 1,
        }
    finally:
        os.remove(db_path)


def test_log_everything_persists_scans_and_auth_results_together():
    db_path = make_temp_db()
    try:
        database.init_db(db_path=db_path, seed_defaults=False)
        analyzed = [{"ssid": "A", "bssid": "aa:aa:aa:aa:aa:aa", "status": "CANDIDATE_TRUSTED", "channel": 1, "signal": 1, "security": "WPA2", "ts": "t"}]
        auth_results = [{"ap": {"ssid": "A", "bssid": "aa:aa:aa:aa:aa:aa"}, "auth_result": "SUCCESS", "reason": "ok", "session_key": b"\x00" * 32}]

        database.log_everything(analyzed, auth_results, db_path=db_path)

        assert len(database.get_recent_scans(db_path=db_path)) == 1
        assert len(database.get_auth_results(db_path=db_path)) == 1
    finally:
        os.remove(db_path)
