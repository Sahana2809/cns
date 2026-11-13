
import os

from crypto.key_exchange import (
    generate_ephemeral_key_pair,
    get_public_key_bytes,
    derive_session_key
)


def test_x25519_key_exchange():

    # Analyzer generates its key pair
    analyzer_private, analyzer_public = generate_ephemeral_key_pair()

    # Simulated AP generates its key pair
    ap_private, ap_public = generate_ephemeral_key_pair()

    # Exchange public keys
    analyzer_public_bytes = get_public_key_bytes(analyzer_public)
    ap_public_bytes = get_public_key_bytes(ap_public)

    # Both participants use the same public salt
    salt = os.urandom(32)

    # Analyzer derives the session key
    analyzer_key = derive_session_key(
        analyzer_private,
        ap_public_bytes,
        salt
    )

    # AP derives the session key
    ap_key = derive_session_key(
        ap_private,
        analyzer_public_bytes,
        salt
    )

    # Both keys must be identical
    assert analyzer_key == ap_key

    # Session key must contain 32 bytes (256 bits)
    assert len(analyzer_key) == 32
