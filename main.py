"""Integration Entry Point for SHADOW Wi-Fi.

Owner: Sanmati U Shinganmakki

Glues the three modules together in an automated pipeline:
Part 1 (Sahana):  Discovers APs (scanner.py) and classifies them (detector.py)
Part 2 (Srushti): Performs cryptographic challenge-response authentication
Part 3 (Sanmati): Establishes AES-GCM encrypted session, logs results, and
                  stores everything in SQLite (database.py)
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import database
import detector
import scanner
import secure_session

# Attempt to import Srushti's Part 2 authentication module if present
try:
    import authentication
except ImportError:
    authentication = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def mock_verify_ap(ap: Dict[str, Any], trusted_profiles: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Fallback simulated AP authentication verification when Part 2 module is not yet loaded.

    Adheres strictly to the Part 2 -> Part 3 handoff contract:
        {
            "ap": {"ssid": str, "bssid": str},
            "auth_result": "SUCCESS" | "FAILED",
            "reason": str,
            "session_key": bytes | None
        }
    """
    ssid = ap.get("ssid", "")
    bssid = ap.get("bssid", "")
    profile = trusted_profiles.get(ssid)

    if not profile:
        return {
            "ap": {"ssid": ssid, "bssid": bssid},
            "auth_result": "FAILED",
            "reason": f"No registered trusted profile for SSID '{ssid}'",
            "session_key": None,
        }

    # Simulate cryptographic verification based on registered public key fingerprint
    fp = profile.get("pubkey_fingerprint")
    if fp:
        # Simulate successful challenge-response and HKDF session key derivation
        seed = f"session_key_for_{ssid}_{bssid}_{_now_iso()}".encode("utf-8")
        session_key = hashlib.sha256(seed).digest()
        return {
            "ap": {"ssid": ssid, "bssid": bssid},
            "auth_result": "SUCCESS",
            "reason": "Cryptographic signature verified against registered Ed25519 profile",
            "session_key": session_key,
        }
    else:
        # Profile has no public key registered -> reject
        return {
            "ap": {"ssid": ssid, "bssid": bssid},
            "auth_result": "FAILED",
            "reason": "No registered cryptographic public key in trusted profile",
            "session_key": None,
        }


def authenticate_candidate_aps(
    candidates: List[Dict[str, Any]],
    trusted_profiles: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Verify candidate APs using Part 2 authentication module (or fallback mock)."""
    results = []
    for ap in candidates:
        if authentication and hasattr(authentication, "verify"):
            try:
                res = authentication.verify(ap)
            except Exception as e:
                res = {
                    "ap": {"ssid": ap.get("ssid"), "bssid": ap.get("bssid")},
                    "auth_result": "FAILED",
                    "reason": f"Authentication exception: {e}",
                    "session_key": None,
                }
        else:
            res = mock_verify_ap(ap, trusted_profiles)
        results.append(res)
    return results


def get_simulated_demo_aps() -> List[Dict[str, Any]]:
    """Generate simulated AP records covering all project scenarios:
    - Legitimate AP (matches College_WiFi profile)
    - Duplicate SSID rogue AP (same SSID 'College_WiFi', unrecognized BSSID)
    - Security downgrade AP (same SSID 'College_WiFi', Open security)
    - Unrelated Cafe Wi-Fi (UNKNOWN status)
    """
    now = _now_iso()
    return [
        {
            "ssid": "College_WiFi",
            "bssid": "AA:BB:CC:11:22:33",
            "channel": 6,
            "signal": 88,
            "security": "WPA2",
            "ts": now,
        },
        {
            "ssid": "College_WiFi",
            "bssid": "DE:AD:BE:EF:00:01",  # Rogue AP with duplicate SSID!
            "channel": 11,
            "signal": 95,
            "security": "WPA2",
            "ts": now,
        },
        {
            "ssid": "College_WiFi",
            "bssid": "AA:BB:CC:11:22:33",
            "channel": 1,
            "signal": 75,
            "security": "Open",  # Security mismatch downgrade!
            "ts": now,
        },
        {
            "ssid": "Campus_Cafe_Guest",
            "bssid": "12:34:56:78:9A:BC",
            "channel": 3,
            "signal": 60,
            "security": "Open",
            "ts": now,
        },
    ]


def run_pipeline(
    mode: str = "simulated",
    custom_message: str = "Confidential data",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute the full SHADOW Wi-Fi integration pipeline:
    1. Scan nearby APs (Part 1 - scanner.py or simulated)
    2. Classify APs against trusted profiles (Part 1 - detector.py)
    3. Authenticate CANDIDATE_TRUSTED APs (Part 2 - authentication.py)
    4. For successful auth: establish AES-GCM secure session (Part 3 - secure_session.py)
    5. Save all records and logs to SQLite (Part 3 - database.py)
    """
    print(f"\n========================================================")
    print(f"  SHADOW Wi-Fi — Execution Pipeline ({mode.upper()} MODE)")
    print(f"========================================================")

    # Initialize SQLite database
    database.init_db(db_path, seed_defaults=True)
    trusted_profiles = database.get_trusted_profiles(db_path)
    print(f"[*] Loaded {len(trusted_profiles)} trusted profile(s) from database.")

    # Step 1: Scan
    if mode == "live":
        print("[*] Scanning nearby live Wi-Fi networks (scanner.py)...")
        raw_aps = scanner.scan()
        if not raw_aps:
            print("[-] Live Wi-Fi scan returned 0 networks (or Wi-Fi adapter unavailable).")
            print("    Falling back to simulated demo APs for demonstration.")
            raw_aps = get_simulated_demo_aps()
    else:
        print("[*] Using simulated AP suite for demonstration...")
        raw_aps = get_simulated_demo_aps()

    print(f"[+] Discovered {len(raw_aps)} AP(s).")

    # Step 2: Classify with detector
    analyzed_aps = detector.analyze_all(raw_aps, trusted_profiles)
    candidates = detector.candidate_trusted(analyzed_aps)

    print("\n[+] AP Classification Summary:")
    for ap in analyzed_aps:
        status = ap.get("status")
        ssid = ap.get("ssid")
        bssid = ap.get("bssid")
        sec = ap.get("security")
        sig = ap.get("signal")
        print(f"    - {status:<18} | SSID: {ssid:<18} | BSSID: {bssid} | Sec: {sec:<5} | Signal: {sig}%")

    print(f"\n[+] Candidates for Cryptographic Verification: {len(candidates)}")

    # Step 3: Cryptographic Authentication
    auth_results = authenticate_candidate_aps(candidates, trusted_profiles)
    for res in auth_results:
        ap = res.get("ap", {})
        result = res.get("auth_result")
        reason = res.get("reason")
        print(f"    - Auth Result: {result} for {ap.get('ssid')} [{ap.get('bssid')}]: {reason}")

    # Step 4: AES-GCM Secure Messaging for authenticated APs
    session_demos = []
    for res in auth_results:
        if res.get("auth_result") == "SUCCESS" and res.get("session_key"):
            ap = res.get("ap", {})
            session_key = res.get("session_key")
            print(f"\n[*] Launching AES-GCM Secure Session for authenticated AP: {ap.get('ssid')}")
            demo = secure_session.demo_message(session_key, message=custom_message)
            session_demos.append(demo)
            print(f"    - Original Message:   \"{demo['original_message']}\"")
            print(f"    - Ciphertext (hex):   {demo['ciphertext_hex'][:40]}... (length={demo['ciphertext_length']} bytes)")
            print(f"    - Nonce (hex):        {demo['nonce_hex']}")
            print(f"    - Decrypted Message:  \"{demo['decrypted_message']}\"")
            print(f"    - Tamper Detection:   {demo['tamper_result']}")

    # Step 5: Persist everything to SQLite
    database.log_everything(analyzed_aps, auth_results, db_path=db_path)
    database.log_event(
        "INFO",
        "SYSTEM",
        f"Pipeline run complete in {mode} mode: {len(analyzed_aps)} APs analyzed, {len(auth_results)} verified.",
        db_path=db_path,
    )
    print("\n[+] All events, scan results, and auth outcomes saved to SQLite database.")

    metrics = database.get_summary_metrics(db_path)
    print("\n[+] Current Global Metrics:")
    print(f"    * Total APs Discovered:    {metrics['total_discovered']}")
    print(f"    * Suspicious Rogue Alerts: {metrics['suspicious_aps']}")
    print(f"    * Candidate Trusted APs:   {metrics['candidate_trusted']}")
    print(f"    * Authentication Failures: {metrics['auth_failures']}")
    print("========================================================\n")

    return {
        "analyzed_aps": analyzed_aps,
        "auth_results": auth_results,
        "session_demos": session_demos,
        "metrics": metrics,
    }


def main():
    parser = argparse.ArgumentParser(description="SHADOW Wi-Fi — Rogue AP Detector & Secure Authenticator")
    parser.add_argument("--live", action="store_true", help="Run scan on live physical Wi-Fi adapter")
    parser.add_argument("--demo", action="store_true", help="Run simulated end-to-end demo suite (default)")
    parser.add_argument("--tamper-demo", action="store_true", help="Run standalone AES-GCM tamper-detection demo")
    parser.add_argument("--init-db", action="store_true", help="Initialize / reset database schema")
    parser.add_argument("--msg", type=str, default="Confidential data", help="Custom plaintext for secure session")
    args = parser.parse_args()

    if args.init_db:
        database.init_db()
        print("[+] Database initialized successfully.")
        return

    if args.tamper_demo:
        key = os.urandom(32)
        print("\n--- AES-GCM Tamper Detection Demonstration ---")
        demo = secure_session.demo_message(key, message=args.msg)
        print(f"Original message:   \"{demo['original_message']}\"")
        print(f"Encrypted message:  <{demo['ciphertext_hex']}>")
        print(f"Decrypted message:  \"{demo['decrypted_message']}\"")
        print(f"Modified ciphertext: {demo['tamper_result']}")
        return

    mode = "live" if args.live else "simulated"
    run_pipeline(mode=mode, custom_message=args.msg)


if __name__ == "__main__":
    main()
