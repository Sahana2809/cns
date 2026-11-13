"""Rogue AP detection engine (SHADOW Wi-Fi, Part 1).

Classifies discovered APs against a database of trusted AP profiles using
only observable data (SSID, BSSID, security type). This module produces
*indicators* only — SUSPICIOUS and SECURITY_MISMATCH are warning signs,
not proof that an AP is rogue. Cryptographic verification (Part 2,
authentication.py) is the actual trust boundary.
"""

STATUS_CANDIDATE_TRUSTED = "CANDIDATE_TRUSTED"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_SECURITY_MISMATCH = "SECURITY_MISMATCH"
STATUS_UNKNOWN = "UNKNOWN"


def make_trusted_profile(ssid, allowed_bssids, security, pubkey_fingerprint=None, owner=None):
    """Build a trusted AP profile record.

    pubkey_fingerprint is filled in later by Part 2 once a signing keypair
    is registered for this AP; left None until then.
    """
    return {
        "ssid": ssid,
        "allowed_bssids": [b.upper() for b in allowed_bssids],
        "security": security,
        "pubkey_fingerprint": pubkey_fingerprint,
        "owner": owner,
    }


def analyze_ap(ap, trusted_profiles):
    """Classify a single discovered AP against the trusted profile store.

    trusted_profiles: dict mapping ssid -> profile (see make_trusted_profile).
    """
    profile = trusted_profiles.get(ap["ssid"])
    if profile is None:
        return STATUS_UNKNOWN
    if ap["bssid"].upper() not in profile["allowed_bssids"]:
        return STATUS_SUSPICIOUS
    if ap["security"] != profile["security"]:
        return STATUS_SECURITY_MISMATCH
    return STATUS_CANDIDATE_TRUSTED


def analyze_all(aps, trusted_profiles):
    """Classify a batch of discovered APs, returning each with a status field."""
    return [{**ap, "status": analyze_ap(ap, trusted_profiles)} for ap in aps]


def candidate_trusted(analyzed_aps):
    """APs that passed the observable-data checks and are ready for Part 2's
    cryptographic challenge-response verification.

    Being CANDIDATE_TRUSTED here is not proof of legitimacy by itself.
    """
    return [ap for ap in analyzed_aps if ap["status"] == STATUS_CANDIDATE_TRUSTED]
