# SHADOW Wi-Fi — My Part: Cryptographic Authentication & Key Exchange

**Owner: Srushti B Bammanawadi**
Course: Cryptography and Network Security (26ECSC403)

Full project context: see `PLAN.md` on `main` for the complete 3-way split and demo
strategy. This file is your focused, detailed plan for **Part 2 only**.

---

## 1. What you own

**Files:** `authentication.py`, `crypto/key_generation.py`, `crypto/digital_signature.py`,
`crypto/key_exchange.py`, `simulated_ap/ap_server.py`, `tests/test_authentication.py`

This is the technical core of the CNS submission: proving an AP's *identity*
cryptographically, not just comparing SSID/BSSID (that's Sahana's job, Part 1). Ordinary
Wi-Fi scanning gives you no cryptographic identity for an AP — you must build a
**simulated AP authentication service** to stand in for it.

---

## 2. Input you receive from Part 1 (Sahana)

A list of `CANDIDATE_TRUSTED` AP records:
```python
{"ssid": str, "bssid": str, "channel": int, "signal": int, "security": str, "status": "CANDIDATE_TRUSTED"}
```
You run cryptographic verification on each of these — not on `SUSPICIOUS`/`UNKNOWN` ones.

---

## 3. `crypto/key_generation.py`

- Generate an **Ed25519** signing keypair for each simulated trusted AP.
- Private key stays only inside `simulated_ap/ap_server.py` (never exposed to the
  analyzer side).
- Public key + its fingerprint (e.g. SHA-256 of the raw public key bytes) gets registered
  into the trusted AP profile — this is the `pubkey_fingerprint` field Sahana left as a
  placeholder in her profile schema.

## 4. `simulated_ap/ap_server.py` — the "legitimate AP" stand-in

Runs as a separate local process (can be on its own laptop over the same real LAN/hotspot,
or localhost for a quick test). Responsibilities:
- Hold the Ed25519 private key for each AP it represents.
- Receive a challenge nonce from the analyzer.
- Sign `(nonce, session_info)` and return the signature.
- Participate in the X25519 Diffie–Hellman handshake (step 6 below).

## 5. `authentication.py` — challenge-response protocol (analyzer side)

1. Generate a cryptographically secure random nonce (`os.urandom(32)` or
   `secrets.token_bytes(32)`).
2. Send nonce to `simulated_ap/ap_server.py`.
3. Receive back `(signature, public_key_used)`.
4. **Verify against the previously registered public key from the trusted profile** —
   never trust a public key the AP supplies on the spot; look it up by SSID/BSSID in the
   profile Sahana's module populated.
5. Track consumed nonces (in-memory set, or write through to Sanmati's `database.py`) and
   reject any signature over a nonce that's already been used — this is your replay-attack
   defense.
6. Return `"SUCCESS"` or `"FAILED"` with a reason string for the dashboard/logs.

## 6. `crypto/key_exchange.py` — session key establishment

1. X25519 Diffie–Hellman exchange between analyzer and simulated AP.
2. Derive the session key with **HKDF-SHA256** over the shared secret.
3. Authenticate the exchange transcript using the Ed25519 signing key (so an attacker
   can't just swap in their own DH public value) — sign `(dh_public_value, nonce)`
   alongside the challenge-response signature, or as a second signature over the
   transcript.

## 7. `crypto/digital_signature.py`

Thin wrapper module: `sign(private_key, message) -> bytes`,
`verify(public_key, message, signature) -> bool`. Keep this separate from
`authentication.py` so Sanmati's AES-GCM code and your signature code don't get tangled.

---

## 8. Handoff contract → Part 3 (Sanmati)

```python
{
    "ap": {"ssid": ..., "bssid": ...},
    "auth_result": "SUCCESS" | "FAILED",
    "reason": str,              # e.g. "signature verified", "unknown pubkey", "replayed nonce"
    "session_key": bytes | None,  # only present on SUCCESS, from HKDF output
}
```
Sanmati's `secure_session.py` takes `session_key` and does AES-GCM encryption on top of it
— you don't touch AES-GCM yourself, that's her half of `secure_session.py`.

---

## 9. Your test scenarios

- **Test 1** — registered AP, valid signature → `SUCCESS`.
- **Test 3** — AP with invalid/wrong signature → `FAILED`, reason = signature mismatch.
- **Replay test** — reuse an old valid challenge-response → must be rejected because the
  nonce was already consumed.

These three run against your `simulated_ap/ap_server.py`, which can sit on a real laptop
reachable over the same Wi-Fi as everyone else's devices (so the transport is real even
though the "AP identity" itself is simulated — this is the project's documented boundary,
keep it explicit in your report section).

---

## 10. Build order

1. Key generation + a bare sign/verify round-trip (no networking yet, just functions
   calling each other in one script).
2. Wrap it in `simulated_ap/ap_server.py` as a separate runnable process.
3. Add the nonce challenge-response flow end-to-end in `authentication.py`.
4. Add replay-nonce tracking.
5. Add X25519 + HKDF session key derivation.
6. Write `tests/test_authentication.py` covering Test 1, Test 3, and replay.
