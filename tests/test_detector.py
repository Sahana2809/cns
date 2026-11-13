import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detector import (
    STATUS_CANDIDATE_TRUSTED,
    STATUS_SECURITY_MISMATCH,
    STATUS_SUSPICIOUS,
    STATUS_UNKNOWN,
    analyze_all,
    analyze_ap,
    candidate_trusted,
    make_trusted_profile,
)


def make_ap(ssid, bssid, security, channel=6, signal=80):
    return {"ssid": ssid, "bssid": bssid, "channel": channel, "signal": signal, "security": security, "ts": "t"}


def test_registered_bssid_and_matching_security_is_candidate_trusted():
    profiles = {"College_WiFi": make_trusted_profile("College_WiFi", ["AA:BB:CC:11:22:33"], "WPA2")}
    ap = make_ap("College_WiFi", "AA:BB:CC:11:22:33", "WPA2")
    assert analyze_ap(ap, profiles) == STATUS_CANDIDATE_TRUSTED


def test_same_ssid_unknown_bssid_is_suspicious():
    profiles = {"College_WiFi": make_trusted_profile("College_WiFi", ["AA:BB:CC:11:22:33"], "WPA2")}
    rogue_ap = make_ap("College_WiFi", "AA:BB:CC:11:22:99", "WPA2")
    assert analyze_ap(rogue_ap, profiles) == STATUS_SUSPICIOUS


def test_security_downgrade_is_security_mismatch():
    profiles = {"College_WiFi": make_trusted_profile("College_WiFi", ["AA:BB:CC:11:22:33"], "WPA2")}
    downgraded_ap = make_ap("College_WiFi", "AA:BB:CC:11:22:33", "Open")
    assert analyze_ap(downgraded_ap, profiles) == STATUS_SECURITY_MISMATCH


def test_unregistered_ssid_is_unknown():
    profiles = {"College_WiFi": make_trusted_profile("College_WiFi", ["AA:BB:CC:11:22:33"], "WPA2")}
    ap = make_ap("Random_Cafe_WiFi", "11:22:33:44:55:66", "Open")
    assert analyze_ap(ap, profiles) == STATUS_UNKNOWN


def test_bssid_match_is_case_insensitive():
    profiles = {"College_WiFi": make_trusted_profile("College_WiFi", ["aa:bb:cc:11:22:33"], "WPA2")}
    ap = make_ap("College_WiFi", "AA:BB:CC:11:22:33", "WPA2")
    assert analyze_ap(ap, profiles) == STATUS_CANDIDATE_TRUSTED


def test_analyze_all_tags_every_ap_and_preserves_fields():
    profiles = {"College_WiFi": make_trusted_profile("College_WiFi", ["AA:BB:CC:11:22:33"], "WPA2")}
    aps = [
        make_ap("College_WiFi", "AA:BB:CC:11:22:33", "WPA2"),
        make_ap("College_WiFi", "AA:BB:CC:11:22:99", "WPA2"),
        make_ap("Guest_Network", "DD:EE:FF:44:55:66", "Open"),
    ]
    analyzed = analyze_all(aps, profiles)
    assert [ap["status"] for ap in analyzed] == [
        STATUS_CANDIDATE_TRUSTED,
        STATUS_SUSPICIOUS,
        STATUS_UNKNOWN,
    ]
    assert analyzed[0]["bssid"] == "AA:BB:CC:11:22:33"


def test_candidate_trusted_filters_only_that_status():
    analyzed = [
        {"ssid": "A", "status": STATUS_CANDIDATE_TRUSTED},
        {"ssid": "B", "status": STATUS_SUSPICIOUS},
        {"ssid": "C", "status": STATUS_CANDIDATE_TRUSTED},
    ]
    result = candidate_trusted(analyzed)
    assert [ap["ssid"] for ap in result] == ["A", "C"]


def test_make_trusted_profile_normalizes_bssid_case():
    profile = make_trusted_profile("College_WiFi", ["aa:bb:cc:11:22:33"], "WPA2")
    assert profile["allowed_bssids"] == ["AA:BB:CC:11:22:33"]
    assert profile["pubkey_fingerprint"] is None
