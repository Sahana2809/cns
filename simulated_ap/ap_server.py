
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from crypto.digital_signature import create_auth_message, sign_message
from crypto.key_exchange import (
    generate_ephemeral_key_pair,
    get_public_key_bytes,
    derive_session_key,
    create_exchange_transcript,
    sign_exchange_transcript
)


BASE_DIR = Path(__file__).resolve().parent.parent
PRIVATE_KEY_PATH = BASE_DIR / "simulated_ap" / "ap_private_key.pem"


def load_ap_private_key():
    private_bytes = PRIVATE_KEY_PATH.read_bytes()

    return serialization.load_pem_private_key(
        private_bytes,
        password=None
    )


def respond_to_challenge(nonce, session_info):
    """Sign the initial authentication challenge."""

    private_key = load_ap_private_key()
    message = create_auth_message(nonce, session_info)

    return sign_message(private_key, message)


def respond_to_key_exchange(
    nonce, ap_info, analyzer_public_bytes, salt
):
    """
    Simulated AP creates an ephemeral X25519 key,
    signs the exchange transcript and derives its session key.
    """

    # Generate AP's temporary X25519 key pair
    ap_private, ap_public = generate_ephemeral_key_pair()

    ap_public_bytes = get_public_key_bytes(ap_public)

    # Build the exchange transcript
    transcript = create_exchange_transcript(
        nonce,
        ap_info,
        analyzer_public_bytes,
        ap_public_bytes,
        salt
    )

    # Sign transcript using the AP's registered Ed25519 key
    identity_private_key = load_ap_private_key()
    signature = sign_exchange_transcript(
        identity_private_key,
        transcript
    )

    # AP independently derives its session key
    ap_session_key = derive_session_key(
        ap_private,
        analyzer_public_bytes,
        salt
    )

    # The AP keeps this key internally.
    assert len(ap_session_key) == 32

    return ap_public_bytes, signature
