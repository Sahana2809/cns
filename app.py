"""Streamlit Dashboard for SHADOW Wi-Fi (Part 3).

Owner: Sanmati U Shinganmakki

Displays real-time monitoring and security metrics:
1. 4 Metric Tiles: APs Discovered, Suspicious APs, Candidate Trusted, Auth Failures.
2. 5 Core Sections:
   - Nearby Wi-Fi Networks (Live scan table with security status)
   - Trusted AP Profiles (View and register trusted networks)
   - Suspicious AP Alerts (Rogue APs & security mismatch warnings)
   - Authentication Results (Cryptographic challenge-response outcomes)
   - Security Event Logs (Unified audit timeline)
3. Interactive AES-GCM Secure Session & Tamper Detection Lab
"""

import os
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import database
import detector
import main
import scanner
import secure_session

# Page configuration
st.set_page_config(
    page_title="SHADOW Wi-Fi Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for styling
st.markdown(
    """
    <style>
    .metric-card {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 14px 18px;
        border-left: 4px solid #1f77b4;
    }
    .badge-trusted {
        color: #155724;
        background-color: #d4edda;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-suspicious {
        color: #721c24;
        background-color: #f8d7da;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-mismatch {
        color: #856404;
        background-color: #fff3cd;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-unknown {
        color: #383d41;
        background-color: #e2e3e5;
        padding: 4px 8px;
        border-radius: 4px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize database schema if not already present
database.init_db(seed_defaults=True)

# -----------------------------------------------------------------------------
# SIDEBAR CONTROLS
# -----------------------------------------------------------------------------
st.sidebar.image("https://img.icons8.com/color/96/000000/wifi-router.png", width=64)
st.sidebar.title("SHADOW Wi-Fi")
st.sidebar.caption("Rogue AP Detector & Secure Authenticator")
st.sidebar.markdown("**Course:** CNS (26ECSC403) | **Year:** 2026–27")
st.sidebar.markdown("**Team:** Sahana (116), Srushti (121), Sanmati (141)")

st.sidebar.markdown("---")
st.sidebar.subheader("⚡ Actions & Pipeline")

if st.sidebar.button("📡 Run Live Wi-Fi Scan", use_container_width=True, help="Scan local network via netsh/nmcli"):
    with st.spinner("Scanning Wi-Fi environment and classifying APs..."):
        res = main.run_pipeline(mode="live")
        st.sidebar.success(f"Discovered {len(res['analyzed_aps'])} APs!")
        st.rerun()

if st.sidebar.button("🧪 Run Simulated Demo Suite", use_container_width=True, help="Run standard 4-scenario project demo"):
    with st.spinner("Executing end-to-end simulation suite..."):
        res = main.run_pipeline(mode="simulated")
        st.sidebar.success("Simulated suite executed & logged!")
        st.rerun()

if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
    st.rerun()

st.sidebar.markdown("---")
with st.sidebar.expander("⚙️ Database Operations"):
    if st.button("Re-seed Default Profiles", use_container_width=True):
        database.init_db(seed_defaults=True)
        st.success("Default profiles restored!")
        st.rerun()

# -----------------------------------------------------------------------------
# MAIN HEADER & METRIC TILES
# -----------------------------------------------------------------------------
st.title("🛡️ SHADOW Wi-Fi Security Dashboard")
st.markdown(
    "Automated Wi-Fi Access Point discovery, rogue duplicate-SSID detection, "
    "and post-authentication **AES-256-GCM** secure session messaging."
)

# Top 4 Metric Tiles
metrics = database.get_summary_metrics()
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="📡 APs Discovered",
        value=metrics["total_discovered"],
        help="Total access point scans recorded",
    )
with col2:
    st.metric(
        label="🚨 Suspicious Rogue APs",
        value=metrics["suspicious_aps"],
        delta=f"{metrics['suspicious_aps']} alerts",
        delta_color="inverse",
        help="Duplicate SSIDs with unrecognized BSSIDs",
    )
with col3:
    st.metric(
        label="🔒 Candidate Trusted APs",
        value=metrics["candidate_trusted"],
        help="APs matching registered profiles ready for crypto authentication",
    )
with col4:
    st.metric(
        label="❌ Auth Failures",
        value=metrics["auth_failures"],
        delta=f"{metrics['auth_failures']} rejected" if metrics["auth_failures"] > 0 else "0",
        delta_color="inverse",
        help="Cryptographic challenge-response or signature verification failures",
    )

st.markdown("---")

# -----------------------------------------------------------------------------
# 5 CORE SECTIONS (TABS)
# -----------------------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📶 Nearby Networks",
    "🛡️ Trusted AP Profiles",
    "🚨 Suspicious Alerts",
    "🔑 Cryptographic Auth",
    "📜 Security Event Logs",
    "🔐 AES-GCM Crypto Lab",
])

# -----------------------------------------------------------------------------
# TAB 1: Nearby Wi-Fi Networks
# -----------------------------------------------------------------------------
with tab1:
    st.subheader("Discovered Access Points")
    scans = database.get_recent_scans(limit=100)
    if scans:
        df_scans = pd.DataFrame(scans)
        
        # Color coding helper
        def color_status(val):
            if val == "CANDIDATE_TRUSTED":
                return "background-color: #d4edda; color: #155724; font-weight: bold;"
            elif val == "SUSPICIOUS":
                return "background-color: #f8d7da; color: #721c24; font-weight: bold;"
            elif val == "SECURITY_MISMATCH":
                return "background-color: #fff3cd; color: #856404; font-weight: bold;"
            return "background-color: #e2e3e5; color: #383d41;"

        # Use .map() for Pandas >= 2.1, with fallback to .applymap() for older versions
        styler_method = getattr(df_scans.style, "map", getattr(df_scans.style, "applymap", None))
        styled_scans = styler_method(color_status, subset=["status"]) if styler_method else df_scans
        st.dataframe(
            styled_scans,
            use_container_width=True,
            column_config={
                "id": "ID",
                "ssid": "SSID",
                "bssid": "BSSID (MAC)",
                "channel": "Channel",
                "signal": st.column_config.ProgressColumn(
                    "Signal Strength",
                    help="Wi-Fi Signal Strength %",
                    format="%d%%",
                    min_value=0,
                    max_value=100,
                ),
                "security": "Security",
                "status": "Trust Status",
                "scanned_at": "Timestamp",
            },
        )
    else:
        st.info("No APs discovered yet. Click **'Run Live Wi-Fi Scan'** or **'Run Simulated Demo Suite'** in the sidebar.")

# -----------------------------------------------------------------------------
# TAB 2: Trusted AP Profiles
# -----------------------------------------------------------------------------
with tab2:
    st.subheader("Registered Trusted AP Profiles")
    profiles = database.get_trusted_profiles()

    if profiles:
        profile_list = []
        for ssid, data in profiles.items():
            profile_list.append({
                "SSID": ssid,
                "Allowed BSSIDs": ", ".join(data.get("allowed_bssids", [])),
                "Expected Security": data.get("security", ""),
                "Ed25519 Fingerprint": data.get("pubkey_fingerprint") or "None (Unassigned)",
                "Owner / Location": data.get("owner") or "Unassigned",
            })
        st.dataframe(pd.DataFrame(profile_list), use_container_width=True)
    else:
        st.warning("No trusted profiles registered.")

    st.markdown("#### ➕ Register New Trusted AP Profile")
    with st.form("new_profile_form"):
        p_col1, p_col2 = st.columns(2)
        with p_col1:
            new_ssid = st.text_input("Network SSID", placeholder="e.g. Campus_Secure_Net")
            new_bssids = st.text_input(
                "Allowed BSSIDs (comma-separated)",
                placeholder="e.g. AA:BB:CC:11:22:33, AA:BB:CC:11:22:34",
            )
            new_sec = st.selectbox("Expected Security", ["WPA2", "WPA3", "WPA", "Open"])
        with p_col2:
            new_owner = st.text_input("Owner / Department", placeholder="e.g. Main Library AP #2")
            new_fp = st.text_input(
                "Ed25519 Public Key Fingerprint (optional)",
                placeholder="SHA-256 hex fingerprint (leave blank if unassigned)",
            )

        submit_btn = st.form_submit_button("Save Profile")
        if submit_btn:
            if not new_ssid or not new_bssids:
                st.error("SSID and at least one BSSID are required.")
            else:
                bssid_list = [b.strip() for b in new_bssids.split(",") if b.strip()]
                database.save_trusted_profile(
                    ssid=new_ssid,
                    allowed_bssids=bssid_list,
                    security=new_sec,
                    pubkey_fingerprint=new_fp or None,
                    owner=new_owner or None,
                )
                st.success(f"Trusted profile for '{new_ssid}' saved successfully!")
                st.rerun()

# -----------------------------------------------------------------------------
# TAB 3: Suspicious AP Alerts
# -----------------------------------------------------------------------------
with tab3:
    st.subheader("🚨 Security Alerts & Rogue AP Detections")
    alerts = database.get_suspicious_events(limit=50)

    if alerts:
        for alert in alerts:
            event_type = alert.get("event_type")
            is_rogue = (event_type == "SUSPICIOUS_BSSID")
            alert_color = "#f8d7da" if is_rogue else "#fff3cd"
            border_color = "#dc3545" if is_rogue else "#ffc107"

            st.markdown(
                f"""
                <div style="background-color: {alert_color}; border-left: 6px solid {border_color}; padding: 12px; margin-bottom: 12px; border-radius: 6px;">
                    <div style="font-size: 15px; font-weight: 700; color: #333;">
                        {'⚠️ ROGUE AP WARNING: DUPLICATE SSID' if is_rogue else '⚡ SECURITY CONFIGURATION MISMATCH'}
                    </div>
                    <div style="margin: 4px 0; color: #444;">
                        <strong>SSID:</strong> <code>{alert.get('ssid')}</code> &nbsp;|&nbsp; 
                        <strong>BSSID:</strong> <code>{alert.get('bssid')}</code> &nbsp;|&nbsp; 
                        <strong>Timestamp:</strong> {alert.get('timestamp')}
                    </div>
                    <div style="color: #222;">{alert.get('description')}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.success("No active rogue AP alerts or security mismatches detected.")

# -----------------------------------------------------------------------------
# TAB 4: Cryptographic Auth Results
# -----------------------------------------------------------------------------
with tab4:
    st.subheader("Part 2: Cryptographic Challenge-Response Verification")
    auth_list = database.get_auth_results(limit=50)

    if auth_list:
        df_auth = pd.DataFrame(auth_list)

        def style_auth(val):
            if val == "SUCCESS":
                return "background-color: #d4edda; color: #155724; font-weight: bold;"
            return "background-color: #f8d7da; color: #721c24; font-weight: bold;"

        auth_styler_method = getattr(df_auth.style, "map", getattr(df_auth.style, "applymap", None))
        styled_auth = auth_styler_method(style_auth, subset=["auth_result"]) if auth_styler_method else df_auth
        st.dataframe(
            styled_auth,
            use_container_width=True,
            column_config={
                "id": "ID",
                "timestamp": "Verification Time",
                "ssid": "SSID",
                "bssid": "BSSID",
                "auth_result": "Result",
                "reason": "Cryptographic Audit Reason",
                "has_session_key": st.column_config.CheckboxColumn("Session Key Established"),
                "session_key_fingerprint": "Key Fingerprint (SHA-256)",
            },
        )
    else:
        st.info("No cryptographic authentication attempts recorded yet.")

# -----------------------------------------------------------------------------
# TAB 5: Security Event Logs
# -----------------------------------------------------------------------------
with tab5:
    st.subheader("Unified System Audit Timeline")
    logs = database.get_security_logs(limit=100)

    if logs:
        df_logs = pd.DataFrame(logs)
        st.dataframe(
            df_logs,
            use_container_width=True,
            column_config={
                "id": "Log ID",
                "timestamp": "Timestamp",
                "level": "Level",
                "component": "Component",
                "message": "Message",
                "details": "Context Details",
            },
        )
    else:
        st.info("Log timeline is currently empty.")

# -----------------------------------------------------------------------------
# TAB 6: AES-GCM Secure Session & Tamper Lab
# -----------------------------------------------------------------------------
with tab6:
    st.subheader("Part 3: AES-256-GCM Secure Messaging & Tamper Detection Lab")
    st.markdown(
        "Demonstrates authenticated symmetric encryption under the derived session key. "
        "Any in-flight modification of ciphertext or authentication tag is instantly caught."
    )

    lab_col1, lab_col2 = st.columns([1, 1])

    with lab_col1:
        st.markdown("#### 📤 Sender (Encrypt)")
        test_msg = st.text_input("Plaintext Message", value="Confidential Student Records & Grades")
        secret_passphrase = st.text_input("Session Key / Passphrase", value="shadow-wifi-shared-secret-key-32b", type="password")
        aad_data = st.text_input("Associated Data (Optional AAD)", value="SSID=College_WiFi,AuthMode=WPA2")

        simulate_tamper = st.checkbox("Simulate active attacker (tamper with ciphertext)", value=True)

        if st.button("🚀 Encrypt & Transmit", use_container_width=True):
            st.session_state["demo_run"] = True
            key_bytes = secure_session.ensure_key_length(secret_passphrase)
            aad_bytes = aad_data.encode("utf-8") if aad_data else None

            # Encrypt
            nonce, ct = secure_session.encrypt(key_bytes, test_msg, associated_data=aad_bytes)
            st.session_state["nonce"] = nonce
            st.session_state["ciphertext"] = ct
            st.session_state["key_bytes"] = key_bytes
            st.session_state["aad_bytes"] = aad_bytes
            st.session_state["test_msg"] = test_msg
            st.session_state["tampered"] = secure_session.tamper_ciphertext(ct) if simulate_tamper else ct
            st.session_state["was_tampered"] = simulate_tamper

    with lab_col2:
        st.markdown("#### 📥 Receiver (Decrypt & Authenticate)")
        if st.session_state.get("demo_run"):
            nonce = st.session_state["nonce"]
            ct_to_decrypt = st.session_state["tampered"]
            key_bytes = st.session_state["key_bytes"]
            aad_bytes = st.session_state["aad_bytes"]
            was_tampered = st.session_state["was_tampered"]

            st.write("**Transmitted Nonce (96-bit Hex):**")
            st.code(nonce.hex())

            st.write(f"**{'Tampered' if was_tampered else 'Valid'} Ciphertext + Auth Tag:**")
            st.code(ct_to_decrypt.hex())

            try:
                decrypted = secure_session.decrypt(key_bytes, nonce, ct_to_decrypt, associated_data=aad_bytes)
                st.success(f"✅ **Decrypted Plaintext:** {decrypted}")
                st.info("Authentication Tag Verified: Message integrity and authenticity confirmed.")
            except secure_session.AuthenticationTagError as e:
                st.error("❌ **AUTHENTICATION FAILURE**")
                st.warning("AES-GCM Authentication Tag rejected! Tampering or corrupted ciphertext detected.")
                st.caption(str(e))
        else:
            st.info("Enter a message and click **'Encrypt & Transmit'** to inspect the live crypto roundtrip.")
