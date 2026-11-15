# SHADOW Wi-Fi

**Rogue Access Point Detection & Secure Wi-Fi Authentication Analyzer**

A software-based wireless security analyzer that detects potential rogue/fake Wi-Fi
access points imitating trusted networks, and verifies AP legitimacy using
cryptographic authentication — because an SSID alone is never proof of trust.

Course: Cryptography and Network Security (26ECSC403) · Course Guide: Prof. Roopa
Badami
Team: Sahana V Agadi (116) · Srushti B Bammanawadi (121) · Sanmati U Shinganmakki (141)

---

## The problem

Attackers can stand up a fake access point with the **same SSID** as a trusted
network. Since most users identify Wi-Fi only by name, they may unknowingly connect
to the fake AP, exposing themselves to credential theft, man-in-the-middle attacks,
and data interception.

**Core idea:** don't trust a Wi-Fi network just because its name looks familiar —
verify its identity before trusting it.

## How it works

Two things are deliberately kept separate:

1. **Detection from observable data** — SSID, BSSID, channel, security type. This
   can only ever produce *indicators* (duplicate SSID, security downgrade) — never
   proof. See `scanner.py` + `detector.py`.
2. **Cryptographic identity verification** — challenge-response with digital
   signatures, authenticated key exchange. This is the actual trust boundary. See
   `authentication.py`, `crypto/`, `simulated_ap/`.

```
Wi-Fi scan (real or simulated)
        │
        ▼
 scanner.py  →  normalized AP records (ssid, bssid, channel, signal, security)
        │
        ▼
 detector.py  →  CANDIDATE_TRUSTED | SUSPICIOUS | SECURITY_MISMATCH | UNKNOWN
        │ (only CANDIDATE_TRUSTED APs proceed)
        ▼
 authentication.py + crypto/ + simulated_ap/
    → Ed25519 challenge-response, X25519 Diffie–Hellman, HKDF-SHA256 session key
        │
        ▼
 secure_session.py  →  AES-256-GCM encrypted messaging + tamper detection
        │
        ▼
 database.py (SQLite)  →  app.py (Streamlit dashboard)
```

**Important technical boundary:** real Wi-Fi scanning and duplicate-SSID/security
checks are genuinely real (`main.py --live` scans actual nearby networks). No
consumer router speaks a custom Ed25519 challenge-response protocol, though, so a
local `simulated_ap/ap_server.py` process stands in for "the AP's authentication
service" during cryptographic verification — the cryptography itself (Ed25519,
X25519, HKDF, AES-GCM) is real; only the identity being a physical AP is simulated.

## Project structure

```
scanner.py              Wi-Fi AP discovery (Windows netsh / Linux nmcli / macOS)
detector.py              Rogue AP classification against trusted profiles
authentication.py        Challenge-response + authenticated key exchange (analyzer side)
secure_session.py        AES-256-GCM encrypt/decrypt + tamper detection
database.py              SQLite schema: profiles, scans, alerts, auth results, logs
app.py                   Streamlit dashboard
main.py                  End-to-end integration pipeline (--demo / --live / --tamper-demo)
run_tests.py             Test runner helper

crypto/
  key_generation.py      Generates the simulated AP's Ed25519 keypair (local-only, gitignored)
  digital_signature.py   Ed25519 sign/verify helpers
  key_exchange.py         X25519 ephemeral key exchange + HKDF-SHA256 session key derivation

simulated_ap/
  ap_server.py            Stand-in "legitimate AP" identity service (holds the private key)

tests/                    Unit tests for every module above

PLAN.md                   Full three-way project plan and demo strategy
DEMO.md                   Step-by-step script for presenting the project
```

## Setup

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python crypto/key_generation.py   # one-time: generates the simulated AP's keypair
python main.py --init-db          # one-time: creates the SQLite database
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python crypto\key_generation.py
python main.py --init-db
```

## Usage

```bash
python main.py --demo          # full pipeline on a staged set of APs (legit, duplicate-SSID,
                                # security-downgrade, unknown) through to AES-GCM messaging
python main.py --live           # same pipeline, scanning real nearby Wi-Fi networks
python main.py --tamper-demo     # isolated AES-GCM encryption + tamper-detection proof
streamlit run app.py             # interactive dashboard (nearby networks, trusted profiles,
                                  # suspicious alerts, crypto auth log, AES-GCM crypto lab)
```

Run the test suite:
```bash
pytest tests/ -v
```

See `DEMO.md` for a full walkthrough script with talking points, and `PLAN.md` for
the complete project plan, tech stack, and demo strategy behind the three-way split.

## Tech stack

Python · Streamlit · SQLite · Pandas · `cryptography` (Ed25519, X25519, HKDF,
AES-GCM) · Pytest

## Team split

| Part | Owner | Scope |
|---|---|---|
| 1 — AP Discovery & Rogue Detection | Sahana V Agadi | `scanner.py`, `detector.py` |
| 2 — Cryptographic Authentication & Key Exchange | Srushti B Bammanawadi | `authentication.py`, `crypto/`, `simulated_ap/` |
| 3 — Secure Session, Database & Dashboard | Sanmati U Shinganmakki | `secure_session.py`, `database.py`, `app.py`, `main.py` |

See `PLAN.md` for the detailed handoff contracts between parts.
