import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from crypto.key_exchange import (
    generate_ephemeral_key_pair,
    get_public_key_bytes,
    create_exchange_transcript,
    verify_exchange_transcript
)

from simulated_ap.ap_server import respond_to_key_exchange


BASE_DIR = Path(__file__).resolve().parent.parent
PUBLIC_KEY_PATH = BASE_DIR / "data" / "trusted_ap_public.pem"

AP = {
    "ssid": "College_WiFi",
    "bssid": "AA:BB:CC:11:22:33"
}


def load_trusted_public_key():
    return serialization.load_pem_public_key(
        PUBLIC_KEY_PATH.read_bytes()
    )


def test_authenticated_key_exchange_transcript():

    # Analyzer generates its temporary X25519 key pair
    analyzer_private, analyzer_public = generate_ephemeral_key_pair()
    analyzer_public_bytes = get_public_key_bytes(analyzer_public)

    # Generate a fresh nonce and salt
    nonce = os.urandom(32)
    salt = os.urandom(32)

    # Simulated AP generates its key and signs the transcript
    ap_public_bytes, signature = respond_to_key_exchange(
        nonce,
        AP,
        analyzer_public_bytes,
        salt
    )

    # Analyzer reconstructs the same transcript
    transcript = create_exchange_transcript(
        nonce,
        AP,
        analyzer_public_bytes,
        ap_public_bytes,
        salt
    )

    # Verify using the previously registered public key
    trusted_public_key = load_trusted_public_key()

    assert verify_exchange_transcript(
        trusted_public_key,
        transcript,
        signature
    )

    # Tampering must invalidate the signature
    tampered_transcript = transcript + b"tampered"

    assert not verify_exchange_transcript(
        trusted_public_key,
        tampered_transcript,
        signature
    )