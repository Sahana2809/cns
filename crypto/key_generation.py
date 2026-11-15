
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from pathlib import Path

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
AP_DIR = BASE_DIR / "simulated_ap"
DATA_DIR = BASE_DIR / "data"

PRIVATE_KEY_PATH = AP_DIR / "ap_private_key.pem"
PUBLIC_KEY_PATH = DATA_DIR / "trusted_ap_public.pem"


def generate_keys():
    AP_DIR.mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)

    # Do not overwrite an existing key pair accidentally
    if PRIVATE_KEY_PATH.exists() or PUBLIC_KEY_PATH.exists():
        print("A key file already exists.")
        print("Not generating new keys to avoid a key mismatch.")
        return

    # Generate Ed25519 key pair
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Save private key (keep secret; never commit it)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    PRIVATE_KEY_PATH.write_bytes(private_bytes)

    # Save public key (safe to share with the team)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    PUBLIC_KEY_PATH.write_bytes(public_bytes)

    # Calculate SHA-256 fingerprint of public key
    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(public_bytes)
    fingerprint_value = fingerprint.finalize().hex()

    print("Ed25519 key pair generated successfully!")
    print("Private key:", PRIVATE_KEY_PATH)
    print("Public key:", PUBLIC_KEY_PATH)
    print("Public key SHA-256 fingerprint:", fingerprint_value)


if __name__ == "__main__":
    generate_keys()
