# SHADOW Wi-Fi — Demo Script

Follow this top to bottom. Everything here is a command you type yourself — no
internet/AI needed, just a terminal in the project folder.

---

## 0. One-time setup (do this before she arrives)

Open a terminal in the project folder, then:

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python crypto/key_generation.py
python main.py --init-db
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python crypto\key_generation.py
python main.py --init-db
```

What just happened (say this if asked):
- Created an isolated Python environment and installed the project's dependencies.
- `key_generation.py` generated a fresh **Ed25519 keypair** for the simulated trusted AP
  (private key never leaves this machine, public key goes in the trusted profile DB).
- `--init-db` created the SQLite database and seeded one trusted AP profile
  (`College_WiFi`).

Do this setup once, before the demo starts, so you're not waiting on `pip install`
live in front of her.

---

## 1. The 5-minute live demo

Keep your venv activated (prompt should show `(.venv)`). Run these one at a time,
narrating as you go.

### Step 1 — Show the classification engine (Part 1)

```bash
python main.py --demo
```

**What to point at on screen** — the "AP Classification Summary" block:

```
CANDIDATE_TRUSTED  | SSID: College_WiFi       | BSSID: AA:BB:CC:11:22:33 | Sec: WPA2
SUSPICIOUS         | SSID: College_WiFi       | BSSID: DE:AD:BE:EF:00:01 | Sec: WPA2
SECURITY_MISMATCH  | SSID: College_WiFi       | BSSID: AA:BB:CC:11:22:33 | Sec: Open
UNKNOWN            | SSID: Campus_Cafe_Guest  | BSSID: 12:34:56:78:9A:BC | Sec: Open
```

**Say:** "Four access points, same-looking names. The second one has the right SSID
but a BSSID we've never registered — that's a duplicate-SSID rogue AP. The third one
has the registered BSSID but its security dropped from WPA2 to Open — that's a
downgrade attack. The system flags both as *indicators*, not proof — SSID alone is
never enough to trust a network."

Then point at the lines right below:
```
Candidates for Cryptographic Verification: 1
Auth Result: SUCCESS for College_WiFi [...]: Authenticated secure session established
```

**Say:** "Only the one AP that passed the observable checks goes on to cryptographic
verification — Ed25519 challenge-response, then an X25519 Diffie-Hellman key
exchange with HKDF to derive a session key. This is the *real* trust boundary, not
the SSID."

Then the AES-GCM block at the bottom:
```
Original Message:   "Confidential data"
Decrypted Message:  "Confidential data"
Tamper Detection:   AUTHENTICATION FAILURE: ...
```

**Say:** "Once authenticated, we open an AES-256-GCM encrypted session. The message
round-trips correctly, and when we deliberately corrupt the ciphertext in the same
run, the authentication tag catches it immediately — that's integrity protection,
not just confidentiality."

### Step 2 — Show a real live scan (Part 1, real hardware)

```bash
python main.py --live
```

**Say:** "Same pipeline, but this time it's scanning my actual nearby Wi-Fi networks
right now — not simulated data." Point out that real networks show up as `UNKNOWN`
(they're not in the trusted-profile database), which is expected and correct —
*unregistered* doesn't mean *rogue*, it just means "no opinion yet."

### Step 3 — Standalone tamper-detection proof

```bash
python main.py --tamper-demo
```

**Say:** "This isolates just the AES-GCM layer to make the tamper detection obvious
without the rest of the pipeline in the way."

### Step 4 — The dashboard

```bash
streamlit run app.py
```

This opens a browser tab automatically (usually `http://localhost:8501`). Walk
through the tabs in this order:

1. **Nearby Networks** — the live table of every discovered AP with its Trust Status
   column color-coded.
2. **Trusted AP Profiles** — the registered profile(s) the system checks against.
3. **Suspicious Alerts** — just the flagged ones, isolated.
4. **Cryptographic Auth** — real verification log: SSID, BSSID, result, and the
   SHA-256 fingerprint of the session key established.
5. **AES-GCM Crypto Lab** — the interactive part. Type any message, tick "Simulate
   active attacker," click **Encrypt & Transmit**, and show the live
   `AUTHENTICATION FAILURE`. Then untick it and run again to show a clean decrypt —
   this contrast is the strongest visual moment of the demo.

When you're done, go back to the terminal and press `Ctrl+C` to stop Streamlit.

---

## 2. If she asks "is this using real Wi-Fi?"

Be precise, this is the one technical distinction worth getting right:

- **Scanning is real** — `--live` genuinely reads nearby APs via `nmcli`/`netsh`.
- **Duplicate-SSID / security-mismatch detection is real** — it runs on whatever
  the scanner returns, real or simulated.
- **The cryptographic AP identity is simulated** — no consumer router speaks our
  custom Ed25519 challenge-response protocol, so a local Python process
  (`simulated_ap/ap_server.py`) stands in for "the AP's authentication service."
  The crypto itself (Ed25519, X25519, HKDF, AES-GCM) is real, standard-library-grade
  cryptography — only the *identity being an AP* is simulated.

This is the documented boundary from the project plan (`PLAN.md`, section 4) — it's
intentional, not a shortcut you need to apologize for.

---

## 3. Troubleshooting on the day

- **`ModuleNotFoundError`** → you forgot to activate the venv. Re-run the
  `source .venv/bin/activate` (or `.venv\Scripts\Activate.ps1` on Windows) line.
- **`python main.py --live` shows 0 APs** → Wi-Fi adapter/driver issue on that
  machine; just use `--demo` instead, it's the same pipeline with the same crypto.
- **Streamlit says "Port 8501 is already in use"** → an old instance is still
  running; close that terminal/tab, or run `streamlit run app.py --server.port 8502`
  and open that port instead.
- **`FileNotFoundError: ap_private_key.pem`** → you skipped the one-time setup step;
  run `python crypto/key_generation.py` once.
