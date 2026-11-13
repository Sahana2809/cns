# SHADOW Wi-Fi — Project Implementation Plan

**Rogue Access Point Detection & Secure Wi-Fi Authentication Analyzer**
Course: Cryptography and Network Security (26ECSC403) | Course Guide: Prof. Roopa Badami
Team: Sahana V Agadi (116), Srushti B Bammanawadi (121), Sanmati U Shinganmakki (141)

---

## 1. Scope recap

A software-based system that (a) scans nearby Wi-Fi APs and flags suspicious ones using
observable data (SSID/BSSID/security type), and (b) cryptographically verifies AP identity
against a pre-registered trusted profile before trusting it. **Duplicate SSID is a warning
sign, not proof of a rogue AP** — cryptographic verification is the real trust boundary.

Dev environment: team is on **mixed OS** (Windows + Linux laptops), so the scanner must
detect the OS and branch between `netsh wlan` (Windows) and `nmcli` (Linux).

---

## 2. Three-way split

### Part 1 — AP Discovery & Rogue Detection Engine
**Owner: Sahana V Agadi**
**Files:** `scanner.py`, `detector.py`, `tests/test_scanner.py`, `tests/test_detector.py`

- Detect host OS; call `netsh wlan show networks mode=bssid` (Windows) or
  `nmcli -f SSID,BSSID,CHAN,SIGNAL,SECURITY device wifi list` (Linux); parse both into one
  common record:
  ```python
  {"ssid": str, "bssid": str, "channel": int, "signal": int, "security": str, "ts": datetime}
  ```
- Design the trusted-AP profile schema: `ssid`, `allowed_bssids[]`, `expected_security`,
  `pubkey_fingerprint`, `owner/description`.
- Implement `analyze_ap(ap, trusted_profiles)` →
  `CANDIDATE_TRUSTED | SUSPICIOUS | SECURITY_MISMATCH | UNKNOWN`.
- Write the comparison rules table (duplicate SSID + unknown BSSID, security downgrade, etc.)
  exactly as in the spec.
- Produce a clean list of `CANDIDATE_TRUSTED` APs as the handoff contract to Part 2.
- Own **Test 2** (same SSID, unknown BSSID → suspicious warning).

### Part 2 — Cryptographic Authentication & Key Exchange
**Owner: Srushti B Bammanawadi**
**Files:** `authentication.py`, `crypto/key_generation.py`, `crypto/digital_signature.py`,
`crypto/key_exchange.py`, `simulated_ap/ap_server.py`, `tests/test_authentication.py`

- Generate an Ed25519 signing keypair per simulated trusted AP; register the public key in
  the Part 1 trusted-profile DB; keep the private key inside `simulated_ap/ap_server.py` only.
- Challenge-response flow: analyzer issues a fresh random nonce → simulated AP signs
  `(nonce, session info)` with its private key → analyzer verifies against the
  **previously registered** public key (never trust a key the AP just hands over on the spot).
- X25519 Diffie–Hellman key exchange + HKDF-SHA256 to derive the session key; authenticate
  the exchange transcript with the Ed25519 signing key.
- Reject reused nonces (replay protection) — track consumed nonces in-memory or in SQLite.
- Own **Test 1** (valid signature → success), **Test 3** (invalid signature → rejected), and
  the replay test.

### Part 3 — Secure Session, Database, Dashboard & Alerts
**Owner: Sanmati U Shinganmakki**
**Files:** `secure_session.py` (AES-GCM half), `database.py`, `app.py` (Streamlit),
`tests/test_encryption.py`, integration entry point

- AES-GCM encrypt/decrypt with a unique nonce per message; demonstrate a tampered-ciphertext
  message failing the GCM authentication tag.
- SQLite schema: `trusted_profiles`, `discovered_aps`, `suspicious_events`, `auth_results`,
  `security_logs`.
- Streamlit dashboard: 4 metric tiles (APs discovered / suspicious / candidate-trusted /
  auth failures) + 5 sections (nearby networks, trusted profiles, suspicious alerts, auth
  results, security logs).
- Wire the pipeline end-to-end: Part 1 scan → Part 1 classify → Part 2 crypto-verify →
  Part 3 session + dashboard + logging. This person owns `main.py`/the integration glue.
- Own **Test 4** (valid encrypted message decrypts) and **Test 5** (modified ciphertext →
  integrity failure), plus final demo assembly.

**Handoff contracts between parts** (fix these early so work can proceed in parallel):
- Part 1 → Part 2: list of `CANDIDATE_TRUSTED` AP dicts with `ssid`/`bssid`.
- Part 2 → Part 3: `{"ap": ..., "auth_result": "SUCCESS"|"FAILED", "session_key": bytes|None}`.
- Everyone → Part 3's `database.py`: every module writes its events through the shared DB
  functions, not directly to SQLite.

---

## 3. Tech stack

| Component | Technology |
|---|---|
| Language | Python |
| Dashboard | Streamlit |
| Wi-Fi scanning | `netsh` (Windows) / `nmcli` (Linux), OS-detected |
| Cryptography | `cryptography` (Ed25519, X25519, HKDF, AES-GCM) |
| Database | SQLite |
| Data handling | Pandas |
| Testing | Pytest |

```
pip install streamlit cryptography pandas pytest
```

---

## 4. Demonstration strategy — real devices vs. simulation

Goal: demonstrate on laptops/phones wherever the behavior is genuinely observable over
real Wi-Fi, and simulate only the piece the spec says ordinary scanning *cannot* provide
(cryptographic AP identity).

| Demo | Real hardware or simulated? | How |
|---|---|---|
| Scenario 1 — legitimate AP detected | **Real** | Scan an actual home/college Wi-Fi, register it as a trusted profile with its real BSSID. |
| Scenario 2 — duplicate SSID | **Real** | Turn two phones into hotspots with the *same SSID* (one matches the registered BSSID, one doesn't) — both show up in a real scan, Part 1 flags the unregistered BSSID as `SUSPICIOUS`. |
| Security mismatch | **Real** | Set one hotspot to WPA2 and a same-SSID hotspot to Open — real scan shows `SECURITY_MISMATCH`. |
| Scenario 3 — cryptographic auth failure | **Simulated** | Real consumer hotspots (phone/laptop) don't support a custom challenge-response protocol. Run `simulated_ap/ap_server.py` locally (can be on a laptop reachable over the same real Wi-Fi/LAN, or just localhost) acting as the "AP's authentication service." Demo both a correctly-signed response (success) and a deliberately wrong/missing key (rejected). |
| Scenario 4 — secure session + tamper detection | **Simulated** (crypto layer) over a **real network link** | Run the Diffie–Hellman handshake and AES-GCM messaging between two real laptops/phones on the same LAN/hotspot, so the *transport* is real even though the "AP identity service" is a simulated Python process. |

This matches the spec's explicit boundary: real scanning proves AP *presence and observable
config*; the simulated AP authentication service proves *cryptographic identity* — don't
blur the two in the report or presentation.

---

## 5. Development schedule

| Phase | Work | Primary owner |
|---|---|---|
| 1 | Env setup, repo/folder structure, shared data contracts | All |
| 2 | Wi-Fi scanning (cross-OS) | Sahana |
| 3 | Trusted AP DB + detection engine | Sahana |
| 4 | Challenge-response + Ed25519 signatures + simulated AP service | Srushti |
| 5 | X25519 Diffie–Hellman + HKDF session key | Srushti |
| 6 | AES-GCM secure session + SQLite schema | Sanmati |
| 7 | Dashboard + alerts + integration of all 3 parts | Sanmati (+ all for integration) |
| 8 | Run the 5 test scenarios on real devices, fix issues, prepare demo + report | All |

---

## 6. Recommended folder structure

```
SHADOW-WIFI/
├── app.py                     (Sanmati)
├── scanner.py                 (Sahana)
├── detector.py                (Sahana)
├── authentication.py          (Srushti)
├── secure_session.py          (Srushti: key exchange / Sanmati: AES-GCM)
├── database.py                (Sanmati)
├── main.py                    (Sanmati — integration)
│
├── crypto/
│   ├── key_generation.py      (Srushti)
│   ├── digital_signature.py   (Srushti)
│   └── key_exchange.py        (Srushti)
│
├── simulated_ap/
│   └── ap_server.py           (Srushti)
│
├── tests/
│   ├── test_scanner.py        (Sahana)
│   ├── test_detector.py       (Sahana)
│   ├── test_authentication.py (Srushti)
│   └── test_encryption.py     (Sanmati)
│
├── data/
│   └── shadow_wifi.db
│
├── PLAN.md
└── requirements.txt
```

---

## 7. Evaluation criteria to keep in mind

Detection accuracy on controlled test cases, authentication success/failure correctness,
encryption/decryption verification, message-tampering detection, and communication
overhead. Keep the report/demo framing consistent: SSID-based signals are *indicators*,
cryptographic verification is *proof*.
