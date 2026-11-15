"""Tests for the public-key fingerprint pinning added to authentication.py.

A valid Ed25519 signature only proves the signer holds whatever private key
pairs with data/trusted_ap_public.pem - it says nothing about whether that
is still the key a given SSID was registered with. These tests confirm
that a registered-but-mismatched fingerprint is rejected even when the
signature itself is perfectly valid, and that authentication still works
when no fingerprint has been registered (backward compatibility with the
project's pre-pinning behavior).
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import database
from authentication import PUBLIC_KEY_PATH, verify_ap_response
from simulated_ap.ap_server import respond_to_challenge

AP = {
    "ssid": "College_WiFi",
    "bssid": "AA:BB:CC:11:22:33",
}


def _temp_db_with_fingerprint(fingerprint):
    """Create a scratch SQLite DB seeded with one trusted profile."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.init_db(db_path=path, seed_defaults=False)
    database.save_trusted_profile(
        ssid=AP["ssid"],
        allowed_bssids=[AP["bssid"]],
        security="WPA2",
        pubkey_fingerprint=fingerprint,
        db_path=path,
    )
    return path


def _real_fingerprint():
    import hashlib
    return hashlib.sha256(PUBLIC_KEY_PATH.read_bytes()).hexdigest()


def test_matching_fingerprint_allows_authentication():
    db_path = _temp_db_with_fingerprint(_real_fingerprint())
    try:
        nonce = os.urandom(32)
        signature = respond_to_challenge(nonce, AP)
        result = verify_ap_response(nonce, AP, signature, db_path=db_path)
        assert result["auth_result"] == "SUCCESS"
    finally:
        os.remove(db_path)


def test_mismatched_fingerprint_rejects_even_with_valid_signature():
    wrong_fingerprint = "00" * 32  # well-formed hex, but not the real key's fingerprint
    db_path = _temp_db_with_fingerprint(wrong_fingerprint)
    try:
        nonce = os.urandom(32)
        signature = respond_to_challenge(nonce, AP)
        result = verify_ap_response(nonce, AP, signature, db_path=db_path)
        assert result["auth_result"] == "FAILED"
        assert "fingerprint mismatch" in result["reason"].lower()
    finally:
        os.remove(db_path)


def test_no_registered_fingerprint_falls_back_to_signature_only():
    db_path = _temp_db_with_fingerprint(None)
    try:
        nonce = os.urandom(32)
        signature = respond_to_challenge(nonce, AP)
        result = verify_ap_response(nonce, AP, signature, db_path=db_path)
        assert result["auth_result"] == "SUCCESS"
    finally:
        os.remove(db_path)


def test_unavailable_database_does_not_break_authentication():
    """If the DB file path is unwritable/unreachable, pinning must fail
    open to signature-only verification rather than crash the pipeline."""
    nonce = os.urandom(32)
    signature = respond_to_challenge(nonce, AP)
    result = verify_ap_response(nonce, AP, signature, db_path="/nonexistent-dir/does-not-exist.db")
    assert result["auth_result"] == "SUCCESS"
