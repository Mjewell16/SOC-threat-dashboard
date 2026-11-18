import streamlit as st
import pandas as pd

from utils.styles import load_styles
from utils.data_loader import load_data
from utils.detections import (
    detect_brute_force,
    detect_password_spray,
    detect_account_takeover,
)
from utils.analytics import detect_impossible_travel
from utils.incidents import get_incidents


load_styles()

st.title("User Investigation")
st.caption(
    "Investigate authentication history, risk indicators, detections, and related incidents for a user."
)

# =========================================================
# LOAD DATA
# =========================================================

df = load_data()

if df.empty:
    st.warning("No authentication data is available for investigation.")
    st.stop()

users = sorted(df["username"].dropna().unique())

if not users:
    st.warning("No users are available for investigation.")
    st.stop()

selected_user = st.selectbox("Select User", users)

user_df = df[df["username"] == selected_user].copy()
user_df = user_df.sort_values("event_time", ascending=False)

# =========================================================
# USER DETECTIONS
# =========================================================

brute_force = detect_brute_force(user_df)
account_takeover = detect_account_takeover(user_df)
impossible_travel = detect_impossible_travel(user_df)

# Password spray must be detected against the full environment because the
# behavior is defined by one source targeting multiple users.
password_spray_all = detect_password_spray(df)
user_source_ips = set(user_df["source_ip"].dropna().astype(str))

if not password_spray_all.empty:
    password_spray = password_spray_all[
        password_spray_all["source_ip"].astype(str).isin(user_source_ips)
    ].copy()
else:
    password_spray = pd.DataFrame()

active_detections = []

for detection_name, detection_df in [
    ("Brute Force", brute_force),
    ("Impossible Travel", impossible_travel),
    ("Password Spray", password_spray),
    ("Potential Account Takeover", account_takeover),
]:
    if not detection_df.empty:
        active_detections.append(detection_name)

# =========================================================
# RISK SCORE
# =========================================================

failed_count = int((user_df["status"] == "failed").sum())
success_count = int((user_df["status"] == "success").sum())
unique_ips = int(user_df["source_ip"].nunique())
unique_countries = int(user_df["geo_country"].nunique())

risk_score = min(
    100,
    failed_count * 2
    + max(unique_ips - 1, 0) * 5
    + max(unique_countries - 1, 0) * 10
    + len(active_detections) * 15,
)

if risk_score >= 75:
    risk_level = "Critical"
elif risk_score >= 50:
    risk_level = "High"
elif risk_score >= 25:
    risk_level = "Medium"
else:
    risk_level = "Low"

# =========================================================
# SUMMARY METRICS
# =========================================================

st.subheader(selected_user)

m1, m2, m3, m4, m5 = st.columns(5)

m1.metric("Risk Score", f"{risk_score}/100")
m2.metric("Risk Level", risk_level)
m3.metric("Authentication Events", len(user_df))
m4.metric("Failed Logins", failed_count)
m5.metric("Active Detections", len(active_detections))

st.divider()

summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
summary_col1.metric("Successful Logins", success_count)
summary_col2.metric("Unique Source IPs", unique_ips)
summary_col3.metric("Countries Used", unique_countries)
summary_col4.metric("Devices Used", int(user_df["device_type"].nunique()))

if not user_df.empty:
    first_seen = user_df["event_time"].min()
    last_seen = user_df["event_time"].max()
    st.caption(
        f"Observed from {first_seen.strftime('%m/%d/%Y %I:%M %p')} "
        f"through {last_seen.strftime('%m/%d/%Y %I:%M %p')}"
    )

# =========================================================
# DETECTION FINDINGS
# =========================================================

st.divider()
st.subheader("Detection Findings")

if not active_detections:
    st.success("No active detection rules currently match this user.")
else:
    findings = []

    for name, detection_df in [
        ("Brute Force", brute_force),
        ("Impossible Travel", impossible_travel),
        ("Password Spray", password_spray),
        ("Potential Account Takeover", account_takeover),
    ]:
        if detection_df.empty:
            continue

        for _, row in detection_df.iterrows():
            findings.append(
                {
                    "Detection": name,
                    "Severity": row.get("severity", "Unknown"),
                    "MITRE ATT&CK": row.get("mitre", "Unmapped"),
                    "Evidence": row.get("detection_summary", "Detection threshold matched."),
                }
            )

    st.dataframe(pd.DataFrame(findings), width="stretch", hide_index=True)

# =========================================================
# RELATED INCIDENTS
# =========================================================

st.divider()
st.subheader("Associated Incidents")

incidents = get_incidents()

if not incidents.empty:
    related_incidents = incidents[
        incidents["username"].fillna("").astype(str) == str(selected_user)
    ].copy()
else:
    related_incidents = pd.DataFrame()

if related_incidents.empty:
    st.info("No persistent incidents are currently associated with this user.")
else:
    display_incidents = related_incidents[
        [
            "incident_id",
            "created_at",
            "severity",
            "incident_type",
            "source_ip",
            "status",
            "assigned_to",
            "mitre_technique",
        ]
    ].rename(
        columns={
            "incident_id": "Incident ID",
            "created_at": "Created At",
            "severity": "Severity",
            "incident_type": "Incident Type",
            "source_ip": "Source IP",
            "status": "Status",
            "assigned_to": "Assigned To",
            "mitre_technique": "MITRE ATT&CK",
        }
    )

    st.dataframe(display_incidents, width="stretch", hide_index=True)

    incident_to_open = st.selectbox(
        "Open related incident",
        related_incidents["incident_id"].tolist(),
    )

    if st.button("Investigate Selected Incident", width="stretch"):
        st.session_state.selected_incident_id = incident_to_open
        st.switch_page("pages/6_incident_details.py")

# =========================================================
# LOCATION / SOURCE ANALYSIS
# =========================================================

st.divider()
left_col, right_col = st.columns(2)

with left_col:
    st.subheader("Observed Locations")
    country_activity = (
        user_df.groupby("geo_country")
        .size()
        .reset_index(name="Events")
        .sort_values("Events", ascending=False)
    )
    st.dataframe(country_activity, width="stretch", hide_index=True)

with right_col:
    st.subheader("Source IP Activity")
    ip_activity = (
        user_df.groupby("source_ip")
        .agg(
            Events=("source_ip", "size"),
            Failed=("status", lambda s: int((s == "failed").sum())),
            Successful=("status", lambda s: int((s == "success").sum())),
            Countries=("geo_country", "nunique"),
        )
        .reset_index()
        .sort_values("Events", ascending=False)
        .rename(columns={"source_ip": "Source IP"})
    )
    st.dataframe(ip_activity, width="stretch", hide_index=True)

# =========================================================
# AUTHENTICATION TIMELINE
# =========================================================

st.divider()
st.subheader("Authentication Timeline")

columns = [
    "event_time",
    "status",
    "source_ip",
    "geo_country",
    "device_type",
    "event_type",
]

available_columns = [column for column in columns if column in user_df.columns]

timeline = user_df[available_columns].copy().rename(
    columns={
        "event_time": "Event Time",
        "status": "Status",
        "source_ip": "Source IP",
        "geo_country": "Country",
        "device_type": "Device",
        "event_type": "Event Type",
    }
)

st.dataframe(timeline, width="stretch", hide_index=True)
