
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

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


def verify_ap_response(nonce, ap_info, signature):

    if nonce in USED_NONCES:
        return {
            "auth_result": "FAILED",
            "reason": "Replay attack detected"
        }

    USED_NONCES.add(nonce)

    message = create_auth_message(nonce, ap_info)
    public_key = load_trusted_public_key()

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


def establish_secure_session(ap_info):
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
        challenge_signature
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
