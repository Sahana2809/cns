# SHADOW Wi-Fi — My Part: AP Discovery & Rogue Detection Engine

**Owner: Sahana V Agadi**
Course: Cryptography and Network Security (26ECSC403)

Full project context: see `PLAN.md` on `main` for the complete 3-way split and demo
strategy. This file is your focused, detailed plan for **Part 1 only**.

---

## 1. What you own

**Files:** `scanner.py`, `detector.py`, `tests/test_scanner.py`, `tests/test_detector.py`

You are building the **observation layer**: discover nearby APs and classify them using
only what a normal scan can see (SSID, BSSID, channel, signal, security type). You are
*not* doing cryptographic verification — that's Part 2 (Srushti). Your output feeds
directly into their input.

---

## 2. `scanner.py` — Wi-Fi AP discovery

Team is on mixed OS, so detect the host OS first (`platform.system()`) and branch:

- **Windows:** parse `netsh wlan show networks mode=bssid`
- **Linux:** parse `nmcli -f SSID,BSSID,CHAN,SIGNAL,SECURITY device wifi list`

Normalize both outputs into one consistent record, regardless of OS:

```python
ap = {
    "ssid": "College_WiFi",
    "bssid": "AA:BB:CC:11:22:33",
    "channel": 6,
    "signal": 85,
    "security": "WPA2",
    "ts": "2026-11-13T10:00:00",
}
```

Checklist:
- [ ] OS detection + command dispatch
- [ ] Windows parser (regex/line-split on `netsh` output)
- [ ] Linux parser (split on `nmcli -f ... -t` terse output is easiest to parse reliably)
- [ ] Return `list[dict]` of AP records, deduplicated per scan
- [ ] Handle "no adapter" / command-not-found gracefully (don't crash — return `[]` + log)

---

## 3. `detector.py` — Rogue AP detection engine

### Trusted AP profile schema
```python
profile = {
    "ssid": "College_WiFi",
    "allowed_bssids": ["AA:BB:CC:11:22:33"],
    "security": "WPA2",
    "pubkey_fingerprint": "...",   # filled in later by Srushti's Part 2
    "owner": "Institution IT Dept",
}
```

### Classification rules

| Condition | Result |
|---|---|
| SSID matches trusted profile and BSSID is registered | `CANDIDATE_TRUSTED` |
| Same SSID but unknown BSSID | `SUSPICIOUS` |
| Security mode differs from trusted profile | `SECURITY_MISMATCH` |
| Unknown SSID | `UNKNOWN` |

```python
def analyze_ap(ap, trusted_profiles):
    profile = trusted_profiles.get(ap["ssid"])
    if profile is None:
        return "UNKNOWN"
    if ap["bssid"] not in profile["allowed_bssids"]:
        return "SUSPICIOUS"
    if ap["security"] != profile["security"]:
        return "SECURITY_MISMATCH"
    return "CANDIDATE_TRUSTED"
```

Checklist:
- [ ] Trusted profile store (in-memory dict is fine to start; Sanmati's `database.py`
      will persist it to SQLite later — don't build your own DB layer, just the
      function signature that accepts profiles as input)
- [ ] `analyze_ap()` exactly per the rules table above
- [ ] Batch function: `analyze_all(aps, trusted_profiles) -> list[dict]` that adds a
      `status` field to each AP record
- [ ] **Important:** never label an AP definitively "rogue" from this module alone —
      `SECURITY_MISMATCH`/`SUSPICIOUS` are indicators, not proof. State this clearly
      in your part of the report.

---

## 4. Handoff contract → Part 2 (Srushti)

Give Srushti exactly this:

```python
candidate_trusted_aps = [ap for ap in analyzed if ap["status"] == "CANDIDATE_TRUSTED"]
```

Each item: `{"ssid": str, "bssid": str, "channel": int, "signal": int, "security": str, "status": "CANDIDATE_TRUSTED"}`

She takes it from there and runs cryptographic challenge-response on each.

---

## 5. Your demo scenarios (real hardware)

- **Scenario 1 — legitimate AP:** scan a real Wi-Fi network, register its real BSSID as
  trusted → shows `CANDIDATE_TRUSTED`.
- **Scenario 2 — duplicate SSID:** two phone hotspots, same SSID, only one BSSID
  registered → the other shows `SUSPICIOUS`.
- **Security mismatch:** same SSID, one hotspot WPA2 and one Open → `SECURITY_MISMATCH`.

All three run on real laptops/phones over real Wi-Fi — no simulation needed for your part.

---

## 6. Build order (don't parallelize these within your own part)

1. Get scanning working on your own OS first, print raw AP list to terminal.
2. Add the other OS's parser once the first one works.
3. Hard-code 1–2 trusted profiles, run `analyze_ap()` against real scan output.
4. Write `tests/test_scanner.py` using captured sample `netsh`/`nmcli` text (don't require
   live Wi-Fi hardware to run tests — feed it canned command output).
5. Write `tests/test_detector.py` covering all 4 classification branches.
