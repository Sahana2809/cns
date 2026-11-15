
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def generate_ephemeral_key_pair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def get_public_key_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def derive_session_key(private_key, peer_public_bytes, salt):
    peer_public_key = X25519PublicKey.from_public_bytes(
        peer_public_bytes
    )

    shared_secret = private_key.exchange(peer_public_key)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"SHADOW-WIFI-SESSION-V1"
    ).derive(shared_secret)


def create_exchange_transcript(
    nonce, ap_info, analyzer_public_bytes, ap_public_bytes, salt
):
    """Create a consistent transcript containing both public keys."""

    transcript = {
        "protocol": "SHADOW-WIFI-KEY-EXCHANGE-V1",
        "nonce": nonce.hex(),
        "ssid": ap_info["ssid"],
        "bssid": ap_info["bssid"],
        "analyzer_public_key": analyzer_public_bytes.hex(),
        "ap_public_key": ap_public_bytes.hex(),
        "salt": salt.hex()
    }

    return json.dumps(
        transcript,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def sign_exchange_transcript(private_key, transcript):
    """Sign the exchange transcript with the AP's Ed25519 key."""
    return private_key.sign(transcript)


def verify_exchange_transcript(public_key, transcript, signature):
    """Verify the transcript using the registered AP public key."""

    try:
        public_key.verify(signature, transcript)
        return True
    except InvalidSignature:
        return False
