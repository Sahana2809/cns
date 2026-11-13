
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)

from authentication import verify_ap_response
from crypto.digital_signature import create_auth_message


AP = {
    "ssid": "College_WiFi",
    "bssid": "AA:BB:CC:11:22:33"
}


def test_valid_signature():
    nonce = os.urandom(32)

    result = verify_ap_response(
        nonce,
        AP,
        create_valid_signature(nonce)
    )

    assert result["auth_result"] == "SUCCESS"


def test_invalid_signature():
    nonce = os.urandom(32)

    result = verify_ap_response(
        nonce,
        AP,
        b"invalid-signature"
    )

    assert result["auth_result"] == "FAILED"
    assert result["reason"] == "Invalid digital signature"


def test_replayed_nonce():
    nonce = os.urandom(32)
    signature = create_valid_signature(nonce)

    first = verify_ap_response(nonce, AP, signature)
    second = verify_ap_response(nonce, AP, signature)

    assert first["auth_result"] == "SUCCESS"
    assert second["auth_result"] == "FAILED"
    assert second["reason"] == "Replay attack detected"


def create_valid_signature(nonce):
    from simulated_ap.ap_server import respond_to_challenge
    return respond_to_challenge(nonce, AP)