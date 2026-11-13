# SHADOW Wi-Fi — My Part: Secure Session, Database, Dashboard & Alerts

**Owner: Sanmati U Shinganmakki**
Course: Cryptography and Network Security (26ECSC403)

Full project context: see `PLAN.md` on `main` for the complete 3-way split and demo
strategy. This file is your focused, detailed plan for **Part 3 only**.

---

## 1. What you own

**Files:** `secure_session.py` (AES-GCM half), `database.py`, `app.py` (Streamlit),
`tests/test_encryption.py`, `main.py` (integration entry point)

You close the loop: take Srushti's verified session key, actually encrypt/decrypt
traffic with it, persist everything to SQLite, and surface it all on a live dashboard.
You also own wiring Part 1 → Part 2 → Part 3 together in `main.py`.

---

## 2. Input you receive from Part 2 (Srushti)

```python
{
    "ap": {"ssid": ..., "bssid": ...},
    "auth_result": "SUCCESS" | "FAILED",
    "reason": str,
    "session_key": bytes | None,
}
```

---

## 3. `secure_session.py` — AES-GCM secure messaging

Only runs when `auth_result == "SUCCESS"` and you have a `session_key`.

1. Encrypt a test message with **AES-GCM**, generating a **unique nonce per message**
   (never reuse a nonce with the same key).
2. "Send" the ciphertext + nonce + auth tag to a receiving side (can be the same process
   for the demo, or genuinely two laptops/phones over the same LAN for a stronger demo).
3. Decrypt at the receiving end, verify the auth tag.
4. Reject any message whose auth tag doesn't verify (this is your tamper-detection demo —
   AES-GCM already gives you authenticated encryption, no separate HMAC pass needed for
   this integrity check).

Example to reproduce for the demo/report:
```
Original message:   "Confidential data"
Encrypted message:   <unreadable ciphertext>
Decrypted message:  "Confidential data"
Modified ciphertext: AUTHENTICATION FAILURE
```

Checklist:
- [ ] `encrypt(session_key, plaintext) -> (nonce, ciphertext)`
- [ ] `decrypt(session_key, nonce, ciphertext) -> plaintext` (raises/returns `None` on
      bad tag)
- [ ] Nonce-reuse guard (track used nonces per session key, same pattern as Srushti's
      nonce tracking on the auth side — keep the two independent, different purposes)

---

## 4. `database.py` — SQLite schema

Tables:
- `trusted_profiles` — ssid, allowed_bssids, security, pubkey_fingerprint, owner
  (written by Part 1, read by Part 2)
- `discovered_aps` — every scan result from Part 1, with timestamp
- `suspicious_events` — APs flagged `SUSPICIOUS`/`SECURITY_MISMATCH` by Part 1
- `auth_results` — every Part 2 challenge-response outcome, with reason string
- `security_logs` — a unified timeline of everything above, for the dashboard's log view

Every other module should write through functions you expose here
(`save_scan_result()`, `save_auth_result()`, `log_event()`, etc.) — don't let Sahana or
Srushti write raw SQL from their own files; keep the schema in one place (yours).

---

## 5. `app.py` — Streamlit dashboard

4 metric tiles at the top:
- APs discovered
- Suspicious APs
- Candidate trusted APs
- Authentication failures

5 sections below:
- Nearby Wi-Fi networks (live scan table: SSID, security, status)
- Trusted AP profiles
- Suspicious AP alerts
- Authentication results
- Security event logs

All of this reads from `database.py` — the dashboard itself should contain no business
logic, just queries + display.

---

## 6. `main.py` — integration glue

```
aps = scanner.scan()                                  # Part 1
analyzed = detector.analyze_all(aps, trusted_profiles) # Part 1
candidates = [a for a in analyzed if a["status"] == "CANDIDATE_TRUSTED"]
auth_results = [authentication.verify(ap) for ap in candidates]  # Part 2
for result in auth_results:
    if result["auth_result"] == "SUCCESS":
        secure_session.demo_message(result["session_key"])        # Part 3
database.log_everything(analyzed, auth_results)                   # Part 3
```
You are responsible for making sure this pipeline actually runs without the three parts'
interfaces drifting apart — if Sahana or Srushti change a field name, update this file
and flag it to them.

---

## 7. Your test scenarios

- **Test 4** — valid encrypted message decrypts correctly.
- **Test 5** — modified ciphertext → integrity verification fails.

Run these over a real LAN/hotspot link between two laptops/phones if possible (stronger
demo), or same-process if time is short — either is acceptable since the crypto logic
itself is what's being graded, not the transport.

---

## 8. Build order

1. SQLite schema + `database.py` CRUD functions first — Sahana and Srushti will want to
   write through these as soon as their modules exist.
2. AES-GCM encrypt/decrypt round-trip in isolation (hardcoded key, no session yet).
3. Plug in Srushti's real `session_key` once Part 2 is ready.
4. Build `app.py` against whatever's in the DB so far (even partial data) — iterate the
   dashboard incrementally rather than waiting for everything to be finished.
5. Write `main.py` to stitch all three parts together; this is also your integration
   test — if it runs end-to-end, the project works.
6. `tests/test_encryption.py` for Test 4 and Test 5.
