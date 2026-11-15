
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

try:
    import database
except ImportError:
    database = None

from crypto.digital_signature import (
    create_auth_message,
    verify_signature
)

from crypto.key_exchange import (
    generate_ephemeral_key_pair,
    get_public_key_bytes,
    derive_session_key,
    create_exchange_transcript,
    verify_exchange_transcript
)

from simulated_ap.ap_server import (
    respond_to_challenge,
    respond_to_key_exchange
)


BASE_DIR = Path(__file__).resolve().parent
PUBLIC_KEY_PATH = BASE_DIR / "data" / "trusted_ap_public.pem"

USED_NONCES = set()


def load_trusted_public_key():
    public_bytes = PUBLIC_KEY_PATH.read_bytes()
    return serialization.load_pem_public_key(public_bytes)


def _public_key_fingerprint(public_key) -> str:
    """SHA-256 fingerprint of the PEM-encoded public key.

    Must match the definition crypto/key_generation.py uses when it prints
    and registers the fingerprint, or pinning below would never agree.
    """
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pem_bytes).hexdigest()


def check_pinned_fingerprint(public_key, ssid, db_path=None):
    """Defense-in-depth: confirm the public key loaded from disk is the one
    actually registered for this SSID, not just *a* key that happens to
    verify the signature.

    A signature check alone only proves the signer holds whatever private
    key pairs with PUBLIC_KEY_PATH - it says nothing about whether that is
    still the key this SSID was registered with. Pinning against the
    fingerprint recorded in the trusted profile closes that gap. If no
    fingerprint has been registered yet (or the database isn't available),
    this is a deliberate no-op so authentication still works purely on
    signature verification, matching the project's pre-pinning behavior.

    Returns an error reason string on mismatch, or None if the check passes
    or was skipped.
    """
    if database is None:
        return None
    try:
        profile = database.get_trusted_profiles(db_path=db_path).get(ssid)
    except Exception:
        return None

    expected = profile.get("pubkey_fingerprint") if profile else None
    if not expected:
        return None

    actual = _public_key_fingerprint(public_key)
    if actual.lower() != expected.lower():
        return (
            f"Public key fingerprint mismatch for '{ssid}': "
            f"registered={expected[:16]}... loaded={actual[:16]}..."
        )
    return None


def verify_ap_response(nonce, ap_info, signature, db_path=None):

    if nonce in USED_NONCES:
        return {
            "auth_result": "FAILED",
            "reason": "Replay attack detected"
        }

    USED_NONCES.add(nonce)

    public_key = load_trusted_public_key()

    fingerprint_error = check_pinned_fingerprint(public_key, ap_info.get("ssid"), db_path=db_path)
    if fingerprint_error:
        return {
            "auth_result": "FAILED",
            "reason": fingerprint_error
        }

    message = create_auth_message(nonce, ap_info)

    if not verify_signature(public_key, message, signature):
        return {
            "auth_result": "FAILED",
            "reason": "Invalid digital signature"
        }

    return {
        "auth_result": "SUCCESS",
        "reason": "AP identity verified",
        "ap": ap_info
    }


def authenticate_ap(ap_info):
    nonce = os.urandom(32)
    signature = respond_to_challenge(nonce, ap_info)

    return verify_ap_response(nonce, ap_info, signature)


def establish_secure_session(ap_info, db_path=None):
    """
    Authenticate AP using challenge-response,
    verify key exchange, and derive a session key.
    """

    # STEP 1: Challenge-response authentication
    challenge_nonce = os.urandom(32)

    challenge_signature = respond_to_challenge(
        challenge_nonce,
        ap_info
    )

    challenge_result = verify_ap_response(
        challenge_nonce,
        ap_info,
        challenge_signature,
        db_path=db_path
    )

    if challenge_result["auth_result"] != "SUCCESS":
        return {
            "auth_result": "FAILED",
            "reason": challenge_result["reason"],
            "session_key": None
        }

    # STEP 2: Generate a separate key-exchange nonce
    exchange_nonce = os.urandom(32)

    if exchange_nonce in USED_NONCES:
        return {
            "auth_result": "FAILED",
            "reason": "Replay attack detected",
            "session_key": None
        }

    USED_NONCES.add(exchange_nonce)

    # STEP 3: Generate analyzer's temporary X25519 key pair
    analyzer_private, analyzer_public = generate_ephemeral_key_pair()

    analyzer_public_bytes = get_public_key_bytes(analyzer_public)

    # STEP 4: Generate fresh HKDF salt
    salt = os.urandom(32)

    # STEP 5: Get AP's ephemeral public key and signature
    ap_public_bytes, signature = respond_to_key_exchange(
        exchange_nonce,
        ap_info,
        analyzer_public_bytes,
        salt
    )

    # STEP 6: Reconstruct the signed transcript
    transcript = create_exchange_transcript(
        exchange_nonce,
        ap_info,
        analyzer_public_bytes,
        ap_public_bytes,
        salt
    )

    # STEP 7: Verify using the registered trusted public key
    trusted_public_key = load_trusted_public_key()

    fingerprint_error = check_pinned_fingerprint(trusted_public_key, ap_info.get("ssid"), db_path=db_path)
    if fingerprint_error:
        return {
            "auth_result": "FAILED",
            "reason": fingerprint_error,
            "session_key": None
        }

    if not verify_exchange_transcript(
        trusted_public_key,
        transcript,
        signature
    ):
        return {
            "auth_result": "FAILED",
            "reason": "Key exchange signature verification failed",
            "session_key": None
        }

    # STEP 8: Derive session key after successful verification
    session_key = derive_session_key(
        analyzer_private,
        ap_public_bytes,
        salt
    )

    return {
        "auth_result": "SUCCESS",
        "reason": "Authenticated secure session established",
        "ap": ap_info,
        "session_key": session_key
    }
