"""Unit tests for AES-GCM Secure Session & Tamper Detection (Part 3).

Covers:
- Test 4: Valid encrypted message decrypts correctly.
- Test 5: Modified ciphertext -> integrity verification fails (InvalidTag / AuthenticationTagError).
- Nonce uniqueness and nonce-reuse prevention.
- Associated data authentication.
- Key mismatch handling.
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import secure_session
from secure_session import (
    AuthenticationTagError,
    NonceReuseError,
    decrypt,
    demo_message,
    encrypt,
    reset_nonce_tracker,
    tamper_ciphertext,
)


def setup_function():
    """Reset the consumed nonce registry before each test."""
    reset_nonce_tracker()


def test_test4_valid_encrypted_message_decrypts_correctly():
    """Project Test 4: Valid encrypted message decrypts correctly under the shared session key."""
    session_key = b"01234567890123456789012345678901"
    plaintext = "Confidential Wi-Fi Transmission: Student Grade Data"

    nonce, ciphertext = encrypt(session_key, plaintext)

    assert nonce is not None and len(nonce) == 12
    assert ciphertext != plaintext.encode("utf-8")
    assert len(ciphertext) > len(plaintext)  # includes 16-byte GCM auth tag

    decrypted = decrypt(session_key, nonce, ciphertext)
    assert decrypted == plaintext


def test_test5_modified_ciphertext_integrity_verification_fails():
    """Project Test 5: Modified ciphertext -> integrity verification fails.

    AES-GCM authenticates the entire ciphertext and tag; flipping even a single
    bit must trigger an AuthenticationTagError.
    """
    session_key = b"01234567890123456789012345678901"
    plaintext = "Confidential data"

    nonce, ciphertext = encrypt(session_key, plaintext)

    # Tamper with the ciphertext (e.g. at the first byte)
    tampered_ciphertext = tamper_ciphertext(ciphertext, byte_offset=0)
    assert tampered_ciphertext != ciphertext

    # Decryption must raise AuthenticationTagError
    failed = False
    try:
        decrypt(session_key, nonce, tampered_ciphertext)
    except AuthenticationTagError:
        failed = True

    assert failed, "Tampered ciphertext should have raised AuthenticationTagError!"


def test_tamper_in_auth_tag_fails():
    """Flipping a bit in the trailing 16-byte authentication tag must also fail."""
    session_key = b"session_key_32_bytes_long_123456"
    plaintext = "Sensitive transaction data"

    nonce, ciphertext = encrypt(session_key, plaintext)
    # Flip the very last byte of the ciphertext (which is in the tag)
    tampered_tag = tamper_ciphertext(ciphertext, byte_offset=len(ciphertext) - 1)

    try:
        decrypt(session_key, nonce, tampered_tag)
        assert False, "Tampered tag should not decrypt"
    except AuthenticationTagError:
        pass


def test_different_nonces_generated_for_identical_messages():
    """Encrypting the same plaintext twice must produce different nonces and ciphertexts."""
    session_key = b"session_key_32_bytes_long_123456"
    plaintext = "Identical message content"

    nonce1, ct1 = encrypt(session_key, plaintext)
    nonce2, ct2 = encrypt(session_key, plaintext)

    assert nonce1 != nonce2
    assert ct1 != ct2


def test_nonce_reuse_is_strictly_blocked():
    """Attempting to encrypt twice with the exact same (key, nonce) must raise NonceReuseError."""
    session_key = b"session_key_32_bytes_long_123456"
    fixed_nonce = b"\x01" * 12

    # First use: OK
    encrypt(session_key, "First message", nonce=fixed_nonce)

    # Second use with same nonce: MUST raise NonceReuseError
    reused = False
    try:
        encrypt(session_key, "Second message", nonce=fixed_nonce)
    except NonceReuseError:
        reused = True

    assert reused, "Reusing a nonce must raise NonceReuseError"


def test_associated_data_mismatch_fails():
    """AAD provides authenticated metadata; tampering with AAD must fail verification."""
    session_key = b"session_key_32_bytes_long_123456"
    plaintext = "Payload data"
    aad = b"SSID=College_WiFi,BSSID=AA:BB:CC:11:22:33"

    nonce, ciphertext = encrypt(session_key, plaintext, associated_data=aad)

    # Correct AAD decrypts
    assert decrypt(session_key, nonce, ciphertext, associated_data=aad) == plaintext

    # Tampered AAD fails
    try:
        decrypt(session_key, nonce, ciphertext, associated_data=b"SSID=Fake_WiFi,BSSID=AA:BB:CC:11:22:33")
        assert False, "Mismatched AAD should have failed tag verification"
    except AuthenticationTagError:
        pass


def test_wrong_key_fails_decryption():
    """Attempting to decrypt ciphertext with a different session key fails verification."""
    key1 = b"key1_01234567890123456789012345"
    key2 = b"key2_01234567890123456789012345"

    nonce, ciphertext = encrypt(key1, "Secret payload")
    try:
        decrypt(key2, nonce, ciphertext)
        assert False, "Decryption with incorrect key must fail"
    except AuthenticationTagError:
        pass


def test_demo_message_helper():
    """Verify that the end-to-end demo_message helper produces the expected report structure."""
    key = b"test_key_for_demo_message_12345"
    result = demo_message(key, "Confidential data", log_to_db=False)

    assert result["original_message"] == "Confidential data"
    assert result["decrypt_success"] is True
    assert result["tamper_detected"] is True
    assert "AUTHENTICATION FAILURE" in str(result["tamper_result"])


if __name__ == "__main__":
    # Allow running directly via `python tests/test_encryption.py`
    print("Running encryption tests...")
    tests = [
        test_test4_valid_encrypted_message_decrypts_correctly,
        test_test5_modified_ciphertext_integrity_verification_fails,
        test_tamper_in_auth_tag_fails,
        test_different_nonces_generated_for_identical_messages,
        test_nonce_reuse_is_strictly_blocked,
        test_associated_data_mismatch_fails,
        test_wrong_key_fails_decryption,
        test_demo_message_helper,
    ]
    passed = 0
    for t in tests:
        setup_function()
        try:
            t()
            print(f"  [PASS] {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {t.__name__}: {e}")

    print(f"\nResult: {passed}/{len(tests)} tests passed.")
    if passed != len(tests):
        sys.exit(1)
