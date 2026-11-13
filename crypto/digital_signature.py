
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)


def create_auth_message(nonce, session_info):
    """
    Create a consistent message for signing and verification.
    """

    message = {
        "protocol": "SHADOW-WIFI-AUTH-V1",
        "nonce": nonce.hex(),
        "ssid": session_info["ssid"],
        "bssid": session_info["bssid"]
    }

    return json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def sign_message(private_key, message):
    """
    Sign the authentication message using Ed25519.
    """

    return private_key.sign(message)


def verify_signature(public_key, message, signature):
    """
    Verify an Ed25519 digital signature.

    Returns True if valid, otherwise False.
    """

    try:
        public_key.verify(signature, message)
        return True

    except InvalidSignature:
        return False
