import streamlit as st
import pandas as pd
import json
import altair as alt
from datetime import datetime

from core.triage_engine import analyze_email_threat
from data.sample_emails import SAMPLE_EMAILS
from core.geolocation import FORENSIC_DISCLAIMER

st.set_page_config(
    page_title="SIH26106 | CyberForensics Threat Command",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------- ADVANCED CYBER COMMAND CENTER CSS -----------------
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">

<style>
    /* Global Typography & Background */
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }
    
    code, pre, .mono-font {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Animated Radar Live Pulse Dot */
    .radar-pulse {
        display: inline-block;
        width: 10px;
        height: 10px;
        background: #10B981;
        border-radius: 50%;
        margin-right: 8px;
        box-shadow: 0 0 10px #10B981;
        animation: pulse-glow 1.8s infinite;
        vertical-align: middle;
    }
    @keyframes pulse-glow {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1.15); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    /* Cyber Hero Header */
    .hero-container {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 50%, #0F172A 100%);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 16px;
        padding: 24px 28px;
        margin-bottom: 20px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        position: relative;
        overflow: hidden;
    }
    .hero-container::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; height: 3px;
        background: linear-gradient(90deg, #38BDF8, #818CF8, #34D399);
    }
    .hero-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #FFFFFF, #E2E8F0, #94A3B8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 4px;
        letter-spacing: -0.02em;
    }
    .hero-subtitle {
        color: #94A3B8;
        font-size: 1.05rem;
        font-weight: 500;
    }

    /* Badges */
    .pill-badge {
        display: inline-flex;
        align-items: center;
        padding: 5px 12px;
        border-radius: 9999px;
        font-size: 0.82rem;
        font-weight: 700;
        letter-spacing: 0.03em;
        text-transform: uppercase;
        margin-right: 8px;
        border: 1px solid transparent;
    }
    .pill-sih { background: rgba(37, 99, 235, 0.2); color: #60A5FA; border-color: rgba(96, 165, 250, 0.3); }
    .pill-track { background: rgba(16, 185, 129, 0.2); color: #34D399; border-color: rgba(52, 211, 153, 0.3); }
    .pill-inst { background: rgba(129, 140, 248, 0.2); color: #A5B4FC; border-color: rgba(165, 180, 252, 0.3); }

    /* Glassmorphism Dynamic Priority Card */
    .threat-card-high {
        background: radial-gradient(circle at 20% 20%, rgba(239, 68, 68, 0.25) 0%, rgba(15, 23, 42, 0.85) 90%);
        border: 2px solid #EF4444;
        border-radius: 14px;
        padding: 20px 24px;
        color: #FFFFFF;
        box-shadow: 0 0 25px rgba(239, 68, 68, 0.3), inset 0 0 15px rgba(239, 68, 68, 0.1);
        margin-bottom: 24px;
        backdrop-filter: blur(8px);
    }
    .threat-card-medium {
        background: radial-gradient(circle at 20% 20%, rgba(245, 158, 11, 0.25) 0%, rgba(15, 23, 42, 0.85) 90%);
        border: 2px solid #F59E0B;
        border-radius: 14px;
        padding: 20px 24px;
        color: #FFFFFF;
        box-shadow: 0 0 25px rgba(245, 158, 11, 0.3), inset 0 0 15px rgba(245, 158, 11, 0.1);
        margin-bottom: 24px;
        backdrop-filter: blur(8px);
    }
    .threat-card-low {
        background: radial-gradient(circle at 20% 20%, rgba(16, 185, 129, 0.25) 0%, rgba(15, 23, 42, 0.85) 90%);
        border: 2px solid #10B981;
        border-radius: 14px;
        padding: 20px 24px;
        color: #FFFFFF;
        box-shadow: 0 0 25px rgba(16, 185, 129, 0.3), inset 0 0 15px rgba(16, 185, 129, 0.1);
        margin-bottom: 24px;
        backdrop-filter: blur(8px);
    }
    .threat-card-empty {
        background: #1E293B;
        border: 2px dashed #64748B;
        border-radius: 14px;
        padding: 20px 24px;
        color: #E2E8F0;
        margin-bottom: 24px;
    }

    /* Metric Glass Tiles */
    .metric-glass {
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-glass:hover {
        transform: translateY(-2px);
        border-color: rgba(56, 189, 248, 0.4);
    }
    .metric-val {
        font-size: 1.85rem;
        font-weight: 800;
        color: #F8FAFC;
        line-height: 1.2;
    }
    .metric-label {
        font-size: 0.82rem;
        color: #94A3B8;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 4px;
    }

    /* Interactive Evidence Blocks */
    .evidence-card {
        background: #0F172A;
        border: 1px solid rgba(148, 163, 184, 0.12);
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 10px;
        position: relative;
        transition: all 0.2s ease;
    }
    .evidence-card:hover {
        background: #1E293B;
        border-color: rgba(56, 189, 248, 0.3);
    }
    .evidence-high { border-left: 5px solid #EF4444; }
    .evidence-med { border-left: 5px solid #F59E0B; }
    .evidence-low { border-left: 5px solid #10B981; }

    /* Hop Step Visualizer */
    .hop-node {
        background: #1E293B;
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 8px;
        padding: 10px 14px;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- 1. REVISION & RE-ACTIVE STATE SYNC -----------------
DEFAULT_SAMPLE = "1. High Risk: Spoofed PayPal Security Suspension (Full Headers)"

if "email_text_key" not in st.session_state:
    st.session_state["email_text_key"] = SAMPLE_EMAILS[DEFAULT_SAMPLE]

def on_sample_change():
    chosen = st.session_state.get("sample_selector")
    if chosen and chosen in SAMPLE_EMAILS:
        st.session_state["email_text_key"] = SAMPLE_EMAILS[chosen]

# ----------------- SIDEBAR -----------------
with st.sidebar:
    st.markdown("""
        <div style="text-align: center; margin-bottom: 12px;">
            <div style="font-size: 2.8rem; filter: drop-shadow(0 0 12px rgba(56, 189, 248, 0.5));">🛡️</div>
            <h3 style="margin: 0; color: #FFFFFF; font-weight: 800;">HYPNEXIS '26</h3>
            <span style="font-size: 0.8rem; color: #38BDF8; font-weight: 700; letter-spacing: 0.08em;">FORENSIC CYBER SHIELD</span>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("**Problem Statement:** `SIH26106`")
    st.markdown("**Theme:** Blockchain & Cybersecurity")
    st.markdown("**Team:** `<Hypnexis '26>`")
    st.markdown("**Institution:** Manipal University Jaipur")
    st.markdown("---")

    st.subheader("⚡ Quick-Load Test Scenarios")
    st.selectbox(
        "Choose a synthetic attack/benign sample:",
        ["-- Select Scenario --"] + list(SAMPLE_EMAILS.keys()),
        key="sample_selector",
        on_change=on_sample_change
    )

    st.markdown("---")
    st.markdown("#### 📡 Forensic Radar Status")
    st.markdown("""
        <div style="padding: 10px; background: rgba(15, 23, 42, 0.8); border-radius: 8px; font-size: 0.85rem;">
            <div><span class="radar-pulse"></span><strong>LIVE FORENSIC SENSORS</strong></div>
            <div style="color: #94A3B8; margin-top: 6px;">
                • TF-IDF Text Classifier: <strong>Active</strong><br>
                • Sender Spoof Engine: <strong>Active</strong><br>
                • PhishTank Feed Cache: <strong>Loaded</strong><br>
                • MTA Hop GeoResolver: <strong>Ready</strong>
            </div>
        </div>
    """, unsafe_allow_html=True)

# ----------------- 2. HERO DASHBOARD HEADER -----------------
st.markdown("""
<div class="hero-container">
    <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap;">
        <div>
            <div class="hero-title">🛡️ Email Threat Detection & Forensic Intelligence</div>
            <div class="hero-subtitle">Automated Phishing Triage, Hop-by-Hop MTA Geolocation, & Explainable AI Verification</div>
        </div>
        <div style="margin-top: 8px;">
            <span class="pill-badge pill-sih">SIH26106</span>
            <span class="pill-badge pill-track">Cybersecurity</span>
            <span class="pill-badge pill-inst">MU Jaipur</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ----------------- 3. ANALYZE CURRENT TEXT -----------------
current_text = st.session_state.get("email_text_key", "").strip()

if current_text:
    analysis = analyze_email_threat(current_text)
else:
    analysis = {
        "priority": "AWAITING INPUT",
        "priority_label": "Awaiting Email Input",
        "priority_color": "#64748B",
        "threat_score": 0,
        "score_breakdown": {"ml_score": 0, "rule_score": 0, "url_score": 0},
        "parsed": {},
        "ml_results": {"phishing_probability": 0, "top_keywords": []},
        "rule_results": {"findings": []},
        "url_results": {"total_urls": 0, "url_details": []},
        "geo_results": None,
        "evidence": [{"source": "System", "severity": "INFO", "detail": "Paste an email message or select a test scenario from the sidebar to begin analysis."}],
        "safe_steps": ["Paste an email message or select a test scenario to begin triage."]
    }

parsed = analysis.get("parsed", {})
score = analysis["threat_score"]
priority = analysis["priority"]

# ----------------- 4. DYNAMIC HIGH-IMPACT THREAT BANNER -----------------
if priority == "HIGH":
    banner_class = "threat-card-high"
    status_icon = "🚨 CRITICAL THREAT DETECTED"
    badge_desc = "High probability of deceptive brand spoofing, malicious links, or credential theft."
elif priority == "MEDIUM":
    banner_class = "threat-card-medium"
    status_icon = "⚠️ SUSPICIOUS ACTIVITY — CAUTION"
    badge_desc = "Pressure tactics or ambiguous sender attributes require human verification before acting."
elif priority == "LOW":
    banner_class = "threat-card-low"
    status_icon = "✅ LOW RISK VERDICT — BENIGN"
    badge_desc = "Linguistic markers and domain signatures conform to standard legitimate communications."
else:
    banner_class = "threat-card-empty"
    status_icon = "⚪ SYSTEM READY — AWAITING INPUT"
    badge_desc = "Select a scenario from the sidebar or paste raw email headers and body below."

st.markdown(f"""
<div class="{banner_class}">
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
        <div>
            <div style="font-size: 0.9rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; opacity: 0.9;">
                {status_icon}
            </div>
            <div style="font-size: 1.7rem; font-weight: 800; margin: 4px 0;">
                Review Priority: <span style="text-decoration: underline;">{priority}</span>
            </div>
            <div style="font-size: 0.95rem; opacity: 0.85;">
                {badge_desc}
            </div>
        </div>
        <div style="text-align: right; margin-top: 8px;">
            <div style="font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.8;">
                Overall Threat Index
            </div>
            <div style="font-size: 3.2rem; font-weight: 900; line-height: 1;">
                {score}<span style="font-size: 1.4rem; font-weight: 500; opacity: 0.6;">/100</span>
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ----------------- 5. EXECUTIVE METRIC TILES -----------------
col_m1, col_m2, col_m3, col_m4 = st.columns(4)

with col_m1:
    st.markdown(f"""
        <div class="metric-glass">
            <div class="metric-label">Composite Risk</div>
            <div class="metric-val" style="color: {'#EF4444' if score >= 60 else ('#F59E0B' if score >= 30 else '#10B981')};">{score}%</div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 4px;">Weighted multi-vector score</div>
        </div>
    """, unsafe_allow_html=True)

with col_m2:
    ml_s = analysis["score_breakdown"]["ml_score"]
    st.markdown(f"""
        <div class="metric-glass">
            <div class="metric-label">AI Text Classifier</div>
            <div class="metric-val" style="color: #60A5FA;">{ml_s}%</div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 4px;">TF-IDF + Logistic Reg</div>
        </div>
    """, unsafe_allow_html=True)

with col_m3:
    rule_s = analysis["score_breakdown"]["rule_score"]
    st.markdown(f"""
        <div class="metric-glass">
            <div class="metric-label">Domain & Spoof Rules</div>
            <div class="metric-val" style="color: #F472B6;">{rule_s}%</div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 4px;">Brand & Header Heuristics</div>
        </div>
    """, unsafe_allow_html=True)

with col_m4:
    url_s = analysis["score_breakdown"]["url_score"]
    st.markdown(f"""
        <div class="metric-glass">
            <div class="metric-label">URL Reputation</div>
            <div class="metric-val" style="color: #34D399;">{url_s}%</div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 4px;">PhishTank & Redirection Intel</div>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

# ----------------- 6. TABBED WORKSPACE -----------------
tab_input, tab_triage, tab_geo, tab_urls, tab_export = st.tabs([
    "📥 1. Live Input & Inspection",
    "📊 2. AI Threat Analysis & Vectors",
    "🌍 3. Relay Hop-by-Hop GeoMap",
    "🔗 4. URL Threat Intelligence",
    "📑 5. SOC Incident Report Export"
])

# ----------------- TAB 1: LIVE INPUT -----------------
with tab_input:
    st.subheader("Pasted Email Source (RFC 822 Headers or Plain Message Body)")
    
    st.text_area(
        "Enter or inspect email text:",
        height=220,
        key="email_text_key"
    )

    c_b1, c_b2, c_b3 = st.columns([0.22, 0.22, 0.56])
    with c_b1:
        if st.button("🚀 Re-Analyze Email", type="primary", use_container_width=True):
            st.rerun()
    with c_b2:
        if st.button("🧹 Clear Input", use_container_width=True):
            st.session_state["email_text_key"] = ""
            st.rerun()

    st.markdown("---")
    st.markdown("#### 🔎 Structured Header Inspector")
    hp1, hp2, hp3 = st.columns(3)
    with hp1:
        st.markdown(f"**From (Display Name):** `{parsed.get('sender_name') or 'N/A'}`")
        st.markdown(f"**Sender Email:** `{parsed.get('sender_email') or 'N/A'}`")
    with hp2:
        st.markdown(f"**Sender Domain:** `{parsed.get('sender_domain') or 'N/A'}`")
        st.markdown(f"**Reply-To Domain:** `{parsed.get('reply_to_domain') or 'Matches Sender'}`")
    with hp3:
        st.markdown(f"**Subject:** *{parsed.get('subject') or '(No Subject)'}*")
        st.markdown(f"**Extracted Origin IP:** `{parsed.get('origin_ip') or 'None detected'}`")

# ----------------- TAB 2: AI THREAT ANALYSIS & VECTORS -----------------
with tab_triage:
    st.subheader("Multidimensional Security Vector Breakdown")

    col_chart, col_explain = st.columns([0.5, 0.5])

    with col_chart:
        st.markdown("##### 📈 Threat Vector Distribution")
        # Visual interactive Bar Chart with Altair
        vectors = [
            {"Vector": "AI Linguistic Model", "Score": analysis["score_breakdown"]["ml_score"]},
            {"Vector": "Domain / Brand Spoof", "Score": min(rule_s, 100)},
            {"Vector": "Urgency & Coercion", "Score": 85 if analysis["rule_results"].get("urgency_detected") else 15},
            {"Vector": "Credential / Payment", "Score": 90 if analysis["rule_results"].get("credential_harvesting") else 10},
            {"Vector": "URL Reputation Risk", "Score": url_s}
        ]
        df_vec = pd.DataFrame(vectors)

        bar_chart = alt.Chart(df_vec).mark_bar(cornerRadius=8, size=24).encode(
            x=alt.X('Score:Q', scale=alt.Scale(domain=[0, 100]), title="Threat Weight (%)"),
            y=alt.Y('Vector:N', sort='-x', title=None),
            color=alt.Color('Score:Q', scale=alt.Scale(scheme='redyellowgreen', reverse=True), legend=None),
            tooltip=['Vector', 'Score']
        ).properties(height=260)

        st.altair_chart(bar_chart, use_container_width=True)

        # AI Linguistic Token Chips
        if analysis["ml_results"].get("top_keywords"):
            st.markdown("##### 🧠 Influential Linguistic Trigger Words")
            kw_html = " ".join([
                f'<span style="background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); color: #FCA5A5; padding: 4px 10px; border-radius: 6px; font-size: 0.85rem; font-family: monospace; display: inline-block; margin: 3px;"><strong>{k}</strong> ({v})</span>'
                for k, v in analysis["ml_results"]["top_keywords"]
            ])
            st.markdown(kw_html, unsafe_allow_html=True)

    with col_explain:
        st.markdown("##### 📋 Synthesized Forensic Evidence")
        for ev in analysis["evidence"]:
            sev = ev.get("severity", "INFO")
            css = "evidence-high" if sev in ("HIGH", "MALICIOUS") else ("evidence-med" if sev in ("MEDIUM", "SUSPICIOUS") else "evidence-low")
            st.markdown(f"""
                <div class="evidence-card {css}">
                    <span style="font-size: 0.75rem; font-weight: 700; text-transform: uppercase; color: #94A3B8; letter-spacing: 0.05em;">
                        {ev['source']} • <strong style="color: {'#EF4444' if sev in ('HIGH', 'MALICIOUS') else ('#F59E0B' if sev in ('MEDIUM', 'SUSPICIOUS') else '#10B981')};">{sev}</strong>
                    </span>
                    <div style="font-size: 0.92rem; color: #E2E8F0; margin-top: 4px;">
                        {ev['detail']}
                    </div>
                </div>
            """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 🛡️ Human-in-the-Loop Defensive Action Plan")
    col_st1, col_st2 = st.columns(2)
    for idx, step in enumerate(analysis["safe_steps"], 1):
        target_col = col_st1 if idx % 2 != 0 else col_st2
        with target_col:
            st.checkbox(f"**Step {idx}:** {step}", value=False, key=f"rec_step_{idx}_{score}")

# ----------------- TAB 3: RELAY HOP GEOMAP -----------------
with tab_geo:
    st.subheader("Originating Mail Transfer Agent (MTA) & Intermediate Relay Trace")

    geo = analysis.get("geo_results")
    if geo and geo.get("status") in ("success", "approximate"):
        gc1, gc2, gc3, gc4 = st.columns(4)
        with gc1:
            st.markdown(f"**Originating Relay IP:** `{geo.get('ip')}`")
        with gc2:
            st.markdown(f"**Country / Region:** `{geo.get('country')}` ({geo.get('region')})")
        with gc3:
            st.markdown(f"**City:** `{geo.get('city')}`")
        with gc4:
            st.markdown(f"**Network ISP / ASN:** `{geo.get('isp')}` ({geo.get('asn')})")

        lat, lon = geo.get("lat"), geo.get("lon")
        if lat and lon and (lat != 0.0 or lon != 0.0):
            st.markdown("##### 📍 Approximate Geographical Location of Relay Server")
            map_data = pd.DataFrame([{"lat": lat, "lon": lon}])
            st.map(map_data, zoom=4)

        st.markdown(f"""
            <div class="disclaimer-box">
                ⚖️ <strong>CISA / Forensic Safe Use Notice:</strong><br>
                {FORENSIC_DISCLAIMER}
            </div>
        """, unsafe_allow_html=True)
    else:
        st.info("No public IP address detected in headers. Choose a scenario with Received headers (e.g., Scenario 1 or 2) to view geolocation mapping.")

    st.markdown("---")
    st.markdown("#### 🔀 Delivery Chain (Received: Hops)")
    hops = parsed.get("received_hops", [])
    if hops:
        for idx, h in enumerate(hops, 1):
            st.markdown(f"""
                <div class="hop-node">
                    <div>
                        <strong style="color: #38BDF8;">Hop #{idx}</strong> — Detected IP(s): <code>{', '.join(h['public_ips']) if h['public_ips'] else 'Internal/Private Gateway'}</code>
                        <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 3px;">{h['raw']}</div>
                    </div>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.caption("No intermediate Received headers detected in the message.")

# ----------------- TAB 4: URL THREAT INTELLIGENCE -----------------
with tab_urls:
    st.subheader("Extracted Embedded Hyperlinks & PhishTank Analysis")
    url_res = analysis.get("url_results", {})
    total_u = url_res.get("total_urls", 0)

    if total_u > 0:
        st.write(f"Total Unique URLs Extracted: **{total_u}**")
        table_rows = []
        for u in url_res.get("url_details", []):
            table_rows.append({
                "Target URL": u["url"],
                "Hostname": u["hostname"],
                "Verdict": u["status"],
                "Risk Score": f"{u['risk_score']}/100",
                "Flagged Indicators": "; ".join(u["flags"]) if u["flags"] else "Clean / Unflagged"
            })
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)
    else:
        st.success("✅ Clean: No external hyperlinks detected in this email message.")

    st.markdown("---")
    st.markdown("#### 📚 Reference Feeds & Threat Intel Standards")
    st.markdown("- **PhishTank Live Database:** Verified crowdsourced repository of active phishing lures.")
    st.markdown("- **CISA Secure Our World:** Guidelines on spotting disguised links and deceptive domains.")

# ----------------- TAB 5: SOC INCIDENT REPORT -----------------
with tab_export:
    st.subheader("Security Operations Center (SOC) Incident Package")
    st.caption("Standardized forensic ticket summary ready for export to Jira, ServiceNow, or Splunk.")

    report_payload = {
        "incident_id": f"INC-SIH26106-{int(datetime.now().timestamp())}",
        "generated_at": datetime.now().isoformat(),
        "platform": "SIH26106 Email Threat Detection & Forensic Intelligence Platform",
        "team": "Hypnexis '26 (Manipal University Jaipur)",
        "verdict": {
            "review_priority": analysis["priority"],
            "composite_threat_index": analysis["threat_score"],
            "ml_text_score": analysis["score_breakdown"]["ml_score"],
            "rule_score": analysis["score_breakdown"]["rule_score"],
            "url_score": analysis["score_breakdown"]["url_score"]
        },
        "sender_metadata": {
            "display_name": parsed.get("sender_name"),
            "email_address": parsed.get("sender_email"),
            "domain": parsed.get("sender_domain")
        },
        "subject": parsed.get("subject"),
        "origin_mta": analysis.get("geo_results", {}),
        "evidence_log": analysis.get("evidence", []),
        "extracted_urls": analysis.get("url_results", {}).get("url_details", []),
        "defensive_steps": analysis.get("safe_steps", []),
        "legal_notice": FORENSIC_DISCLAIMER
    }

    report_str = json.dumps(report_payload, indent=2)

    cx1, cx2 = st.columns(2)
    with cx1:
        st.download_button(
            label="💾 Download JSON SOC Report",
            data=report_str,
            file_name=f"soc_report_{analysis['priority'].lower()}_{int(datetime.now().timestamp())}.json",
            mime="application/json",
            use_container_width=True
        )
    with cx2:
        md_text = f"""# SIH26106 Incident Response Summary
- **Incident ID:** {report_payload['incident_id']}
- **Review Priority:** {analysis['priority']} ({analysis['threat_score']}/100)
- **Subject:** {parsed.get('subject')}
- **Sender:** {parsed.get('sender_name')} <{parsed.get('sender_email')}>
- **Origin MTA IP:** {parsed.get('origin_ip') or 'N/A'}

## Evidence Findings
{chr(10).join([f"- [{e['source']}] {e['detail']}" for e in analysis.get('evidence', [])])}

## Defensive Checklist
{chr(10).join([f"- [ ] {s}" for s in analysis.get('safe_steps', [])])}
"""
        st.download_button(
            label="📝 Download Markdown Summary",
            data=md_text,
            file_name=f"incident_summary_{analysis['priority'].lower()}.md",
            mime="text/markdown",
            use_container_width=True
        )

    st.code(report_str, language="json")
