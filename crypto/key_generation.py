
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
AP_DIR = BASE_DIR / "simulated_ap"
DATA_DIR = BASE_DIR / "data"

PRIVATE_KEY_PATH = AP_DIR / "ap_private_key.pem"
PUBLIC_KEY_PATH = DATA_DIR / "trusted_ap_public.pem"

# This simulated AP identity represents "College_WiFi" everywhere else in the
# project (authentication.py's tests, main.py's demo AP). Keep in sync with
# database.py's seeded profile for that SSID.
AP_SSID = "College_WiFi"
DEFAULT_ALLOWED_BSSIDS = ["AA:BB:CC:11:22:33", "AA:BB:CC:11:22:34"]
DEFAULT_SECURITY = "WPA2"
DEFAULT_OWNER = "Campus IT Admin"

# Running this script directly (`python crypto/key_generation.py`) puts
# crypto/ on sys.path, not the project root, so `import database` would
# otherwise fail. Make the import work regardless of how this is invoked.
sys.path.insert(0, str(BASE_DIR))
try:
    import database
except ImportError:
    database = None


def _fingerprint_of(pem_public_bytes: bytes) -> str:
    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(pem_public_bytes)
    return fingerprint.finalize().hex()


def _sync_fingerprint_to_database(fingerprint_value: str) -> None:
    """Register this fingerprint against the AP's trusted profile.

    Without this, the dashboard's "registered" fingerprint and the key
    authentication.py actually verifies against can silently drift apart -
    database.init_db() seeds a profile with no fingerprint, and nothing
    else ever updates it, so pinning (see authentication.py) would either
    never engage or - worse - could be pinned to a stale value from a
    previous key pair. Re-running this script always re-syncs it.
    """
    if database is None:
        print("Note: 'database' module unavailable; skipping fingerprint sync.")
        return
    database.init_db(seed_defaults=True)
    existing = database.get_trusted_profiles().get(AP_SSID, {})
    database.save_trusted_profile(
        ssid=AP_SSID,
        allowed_bssids=existing.get("allowed_bssids") or DEFAULT_ALLOWED_BSSIDS,
        security=existing.get("security") or DEFAULT_SECURITY,
        pubkey_fingerprint=fingerprint_value,
        owner=existing.get("owner") or DEFAULT_OWNER,
    )
    print(f"Database trusted profile for '{AP_SSID}' updated with this fingerprint.")


def generate_keys():
    AP_DIR.mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)

    # Do not overwrite an existing key pair accidentally, but still make
    # sure the database reflects whatever key is actually on disk.
    if PRIVATE_KEY_PATH.exists() or PUBLIC_KEY_PATH.exists():
        print("A key file already exists.")
        print("Not generating new keys to avoid a key mismatch.")
        if PUBLIC_KEY_PATH.exists():
            fingerprint_value = _fingerprint_of(PUBLIC_KEY_PATH.read_bytes())
            print("Existing public key SHA-256 fingerprint:", fingerprint_value)
            _sync_fingerprint_to_database(fingerprint_value)
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
    fingerprint_value = _fingerprint_of(public_bytes)

    print("Ed25519 key pair generated successfully!")
    print("Private key:", PRIVATE_KEY_PATH)
    print("Public key:", PUBLIC_KEY_PATH)
    print("Public key SHA-256 fingerprint:", fingerprint_value)

    _sync_fingerprint_to_database(fingerprint_value)


if __name__ == "__main__":
    generate_keys()
