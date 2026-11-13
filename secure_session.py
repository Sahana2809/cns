"""AES-GCM Secure Session Messaging & Tamper Detection (SHADOW Wi-Fi, Part 3).

Owner: Sanmati U Shinganmakki

Provides authenticated encryption and decryption using AES-GCM (Galois/Counter Mode).
Runs only after Part 2 successfully authenticates an AP and provides a shared session key.

Key features:
1. AES-256-GCM authenticated encryption (confidentiality + integrity).
2. Unique 96-bit (12-byte) nonce per message with strict nonce-reuse prevention.
3. Cryptographic integrity checking: any modified bit in ciphertext triggers an
   immediate authentication failure (InvalidTag).
4. Full demo runner matching project evaluation criteria.
"""

import hashlib
import os
import secrets
from typing import Dict, Optional, Set, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import database
except ImportError:
    database = None


class NonceReuseError(Exception):
    """Raised when an encryption or decryption attempt reuses a previously consumed nonce."""
    pass


class AuthenticationTagError(Exception):
    """Raised when AES-GCM authentication tag verification fails (ciphertext modified)."""
    pass


# Global or per-session nonce tracker to guarantee nonces are never reused with the same key
_USED_NONCES: Set[Tuple[bytes, bytes]] = set()


def reset_nonce_tracker() -> None:
    """Clear the consumed nonce registry (primarily for testing)."""
    _USED_NONCES.clear()


def ensure_key_length(key: bytes | str) -> bytes:
    """Ensure key is exactly 32 bytes (256 bits) for AES-256.

    If key is a string, hex, or variable-length byte string (e.g. from HKDF or DH),
    hashes it with SHA-256 to produce a canonical 32-byte key.
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    if len(key) in (16, 24, 32):
        return key
    return hashlib.sha256(key).digest()


def generate_nonce() -> bytes:
    """Generate a standard 12-byte (96-bit) cryptographically secure random nonce."""
    return secrets.token_bytes(12)


def encrypt(
    session_key: bytes | str,
    plaintext: str | bytes,
    associated_data: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """Encrypt a plaintext payload using AES-256-GCM.

    Args:
        session_key: 16, 24, or 32-byte key (or raw bytes hashed to 32 bytes).
        plaintext: String or bytes to be encrypted.
        associated_data: Optional unencrypted data authenticated by the tag (AAD).
        nonce: Optional 12-byte nonce. If None, a cryptographically secure random
               nonce is automatically generated.

    Returns:
        (nonce, ciphertext):
        nonce is 12 bytes;
        ciphertext is the encrypted payload with the 16-byte GCM authentication
        tag appended by AESGCM.

    Raises:
        NonceReuseError: If this exact (key_digest, nonce) pair was previously used.
    """
    key = ensure_key_length(session_key)
    key_id = hashlib.sha256(key).digest()

    if nonce is None:
        # Generate until fresh (practically guaranteed on first try with 96-bit space)
        while True:
            candidate = generate_nonce()
            if (key_id, candidate) not in _USED_NONCES:
                nonce = candidate
                break
    else:
        if (key_id, nonce) in _USED_NONCES:
            raise NonceReuseError(
                f"Security violation: Nonce {nonce.hex()} has already been used with this session key! "
                "AES-GCM strictly forbids nonce reuse."
            )

    if isinstance(plaintext, str):
        data = plaintext.encode("utf-8")
    else:
        data = bytes(plaintext)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data)

    # Register nonce as consumed
    _USED_NONCES.add((key_id, nonce))
    return nonce, ciphertext


def decrypt(
    session_key: bytes | str,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: Optional[bytes] = None,
) -> str:
    """Decrypt and verify an AES-256-GCM ciphertext.

    Args:
        session_key: The symmetric key used for encryption.
        nonce: The 12-byte nonce used during encryption.
        ciphertext: The encrypted payload containing the 16-byte GCM auth tag.
        associated_data: Optional AAD that must match what was passed to encrypt.

    Returns:
        The decrypted plaintext decoded as UTF-8 string.

    Raises:
        AuthenticationTagError: If the tag does not verify (indicating message
                                tampering, truncation, or key mismatch).
    """
    key = ensure_key_length(session_key)
    aesgcm = AESGCM(key)

    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return decrypted_bytes.decode("utf-8")
    except InvalidTag as exc:
        raise AuthenticationTagError(
            "AUTHENTICATION FAILURE: AES-GCM authentication tag verification failed. "
            "The message has been tampered with, corrupted, or encrypted with a different key."
        ) from exc


def tamper_ciphertext(ciphertext: bytes, byte_offset: int = 0) -> bytes:
    """Deliberately flip a byte in the ciphertext to simulate an active attacker or network corruption."""
    if not ciphertext:
        return b"\x00"
    data = bytearray(ciphertext)
    target = byte_offset % len(data)
    data[target] ^= 0xFF  # Flip all 8 bits
    return bytes(data)


def demo_message(
    session_key: bytes | str,
    message: str = "Confidential data",
    log_to_db: bool = True,
) -> Dict[str, object]:
    """Execute the end-to-end AES-GCM secure messaging and tamper detection demo.

    Produces output matching the demo report specification:
    1. Original message
    2. Encrypted message (nonce + unreadable ciphertext)
    3. Decrypted message (verified authentication tag)
    4. Tampered ciphertext -> AUTHENTICATION FAILURE (integrity detection)
    """
    key = ensure_key_length(session_key)
    results: Dict[str, object] = {
        "original_message": message,
        "key_fingerprint": hashlib.sha256(key).hexdigest()[:16],
    }

    # Step 1: Encrypt
    nonce, ciphertext = encrypt(key, message)
    results["nonce_hex"] = nonce.hex()
    results["ciphertext_hex"] = ciphertext.hex()
    results["ciphertext_length"] = len(ciphertext)

    # Step 2: Decrypt valid ciphertext
    decrypted = decrypt(key, nonce, ciphertext)
    results["decrypted_message"] = decrypted
    results["decrypt_success"] = (decrypted == message)

    # Step 3: Tamper with ciphertext and verify failure
    tampered = tamper_ciphertext(ciphertext, byte_offset=0)
    results["tampered_ciphertext_hex"] = tampered.hex()

    try:
        decrypt(key, nonce, tampered)
        results["tamper_detected"] = False
        results["tamper_result"] = "ERROR: Tampered message was unexpectedly accepted!"
    except AuthenticationTagError as e:
        results["tamper_detected"] = True
        results["tamper_result"] = "AUTHENTICATION FAILURE: Authentication tag invalid / message tampered"

    # Optional logging to database
    if log_to_db and database:
        try:
            database.log_event(
                "INFO",
                "SESSION",
                f"AES-GCM demo completed: encrypt/decrypt OK, tamper detected={results['tamper_detected']}",
                details={"msg_len": len(message), "key_fp": results["key_fingerprint"]},
            )
        except Exception:
            pass

    return results
