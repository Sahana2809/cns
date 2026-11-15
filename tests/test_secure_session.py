
from authentication import establish_secure_session


def test_complete_secure_session():

    ap = {
        "ssid": "College_WiFi",
        "bssid": "AA:BB:CC:11:22:33"
    }

    result = establish_secure_session(ap)

    assert result["auth_result"] == "SUCCESS"
    assert result["session_key"] is not None
    assert len(result["session_key"]) == 32

    print("\nSecure session established!")
    print("Authentication:", result["auth_result"])
    print("Session key length:", len(result["session_key"]), "bytes")
