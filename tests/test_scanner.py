import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import parse_macos_output, parse_netsh_output, parse_nmcli_output

NMCLI_SAMPLE = (
    r"College_WiFi:AA\:BB\:CC\:11\:22\:33:6:85:WPA2" "\n"
    r"College_WiFi:AA\:BB\:CC\:11\:22\:99:6:40:Open" "\n"
    r"Guest_Network:DD\:EE\:FF\:44\:55\:66:11:70:WPA2"
)

NETSH_SAMPLE = """Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : College_WiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption               : CCMP
    BSSID 1                 : aa:bb:cc:11:22:33
         Signal             : 85%
         Radio type         : 802.11ac
         Channel            : 6
         Basic rates (Mbps) : 1 2 5.5 11
    BSSID 2                 : aa:bb:cc:11:22:99
         Signal             : 40%
         Radio type         : 802.11n
         Channel            : 6

SSID 2 : Guest_Network
    Network type            : Infrastructure
    Authentication          : Open
    Encryption               : None
    BSSID 1                 : dd:ee:ff:44:55:66
         Signal             : 70%
         Radio type         : 802.11n
         Channel            : 11
"""

MACOS_SAMPLE = """Wi-Fi:

      Software Versions:
          CoreWLAN: 14.0

      Interfaces:
          en0:
            Card Type: AirPort Extreme
            Current Network Information:
              College_WiFi:
                PHY Mode: 802.11ac
                Channel: 6
                Network Type: Infrastructure
                Security: WPA2 Personal
                Signal / Noise: -55 dBm / -90 dBm
            Other Local Wi-Fi Networks:
                Guest_Network:
                    PHY Mode: 802.11n
                    Channel: 11
                    Network Type: Infrastructure
                    Security: None
                    Signal / Noise: -70 dBm / -90 dBm
"""


def test_parse_nmcli_output_basic_fields():
    aps = parse_nmcli_output(NMCLI_SAMPLE)
    assert len(aps) == 3
    first = aps[0]
    assert first["ssid"] == "College_WiFi"
    assert first["bssid"] == "AA:BB:CC:11:22:33"
    assert first["channel"] == 6
    assert first["signal"] == 85
    assert first["security"] == "WPA2"


def test_parse_nmcli_output_normalizes_open_security():
    aps = parse_nmcli_output(NMCLI_SAMPLE)
    second = aps[1]
    assert second["bssid"] == "AA:BB:CC:11:22:99"
    assert second["security"] == "Open"


def test_parse_nmcli_output_duplicate_ssid_distinct_bssid():
    aps = parse_nmcli_output(NMCLI_SAMPLE)
    ssids = [ap["ssid"] for ap in aps]
    assert ssids.count("College_WiFi") == 2
    bssids = {ap["bssid"] for ap in aps if ap["ssid"] == "College_WiFi"}
    assert bssids == {"AA:BB:CC:11:22:33", "AA:BB:CC:11:22:99"}


def test_parse_netsh_output_emits_one_record_per_bssid():
    aps = parse_netsh_output(NETSH_SAMPLE)
    assert len(aps) == 3
    college = [ap for ap in aps if ap["ssid"] == "College_WiFi"]
    assert len(college) == 2
    assert {ap["bssid"] for ap in college} == {"AA:BB:CC:11:22:33", "AA:BB:CC:11:22:99"}
    for ap in college:
        assert ap["security"] == "WPA2"
        assert ap["channel"] == 6

    guest = next(ap for ap in aps if ap["ssid"] == "Guest_Network")
    assert guest["bssid"] == "DD:EE:FF:44:55:66"
    assert guest["security"] == "Open"
    assert guest["signal"] == 70
    assert guest["channel"] == 11


def test_parse_netsh_output_empty_input():
    assert parse_netsh_output("") == []


def test_parse_macos_output_basic_fields():
    aps = parse_macos_output(MACOS_SAMPLE)
    ssids = {ap["ssid"] for ap in aps}
    assert "Guest_Network" in ssids
    guest = next(ap for ap in aps if ap["ssid"] == "Guest_Network")
    assert guest["channel"] == 11
    assert guest["security"] == "Open"
    assert guest["signal"] == -70
    assert guest["bssid"].startswith("UNKNOWN-MAC-")
