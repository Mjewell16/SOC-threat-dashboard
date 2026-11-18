import streamlit as st
import pandas as pd
from streamlit_autorefresh import st_autorefresh
from datetime import datetime
from utils.styles import load_styles
from utils.data_loader import load_data
from utils.detections import detect_brute_force, get_threat_level
from utils.analytics import detect_impossible_travel
from utils.detection_rules import DETECTION_RULES, DETECTION_WINDOW_MINUTES
from utils.incidents import get_incidents



st_autorefresh(interval=120000, key="aegis_refresh")

load_styles()





df = load_data()

dashboard_cutoff = pd.Timestamp.now() - pd.Timedelta(hours=24)

dashboard_df = df[
    df["event_time"] >= dashboard_cutoff
].copy()

# Rolling detection window (set in utils/detection_rules.py)
recent_cutoff = pd.Timestamp.now() - pd.Timedelta(minutes=DETECTION_WINDOW_MINUTES)

recent_df = dashboard_df[
    dashboard_df["event_time"] >= recent_cutoff
]

total_events = len(dashboard_df)
failed_logins = recent_df[recent_df["status"] == "failed"]
successful_logins = recent_df[recent_df["status"] == "success"]

# Failed logins per IP (used for the "Top Attacking IPs" chart)
suspicious_ips = (
    failed_logins.groupby("source_ip")
    .size()
    .reset_index(name="failed_attempts")
)

# Brute force alerts use the shared AEGIS-001 rule (same IP + same user)
alerts = detect_brute_force(recent_df)
brute_force_rule = DETECTION_RULES["brute_force"]

# Real incidents from the database, so IDs match the Incident Queue
all_incidents = get_incidents()
incident_queue_df = all_incidents[
    all_incidents["status"] != "Closed"
].copy()

impossible_travel_df = detect_impossible_travel(dashboard_df)

threat_level = get_threat_level(len(alerts), len(failed_logins))

threat_colors = {
    "Low": "#00FF99",
    "Medium": "#FFD166",
    "High": "#FF8C42",
    "Critical": "#FF3B3B"
}

st.title("COMMAND CENTER")
st.caption("Real-time security monitoring and threat detection platform for authentication telemetry.")
# Current date/time
current_time = datetime.now().strftime("%B %d, %Y | %I:%M:%S %p")
st.markdown(
    f"""
    <div style="
        background-color: rgba(20,20,30,0.85);
        padding: 12px 18px;
        border-radius: 14px;
        border: 1px solid rgba(0,255,255,0.2);
        margin-bottom: 20px;
        box-shadow: 0 6px 16px rgba(0,0,0,0.35);
        font-size: 16px;
        color: #00FFFF;
        text-align: center;
        font-weight: 600;
    ">
    SYSTEM TIME: {current_time}
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown("""
<div style="
    background: rgba(15,23,32,0.9);
    border: 1px solid rgba(0,255,200,0.15);
    padding: 10px 18px;
    border-radius: 12px;
    margin-bottom: 20px;
    font-size: 14px;
    color: #D1D5DB;
    display: flex;
    justify-content: space-between;
">
    <span>🟢 SENSOR STATUS: OPERATIONAL</span>
    <span>🛰️ TELEMETRY LINK: ACTIVE</span>
    <span>🔒 AUTH MONITORING: ENABLED</span>
</div>
""", unsafe_allow_html=True)

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Events (24h)", total_events)
col2.metric("Failed Logins (15m)", len(failed_logins))
col3.metric("Successful Logins (15m)", len(successful_logins))
col4.metric("Active Alerts", len(alerts))
with col5:
    st.html(
        f"""
<div style="
    background: rgba(20,30,40,0.95);
    padding: 22px;
    border-radius: 16px;
    border: 1px solid {threat_colors[threat_level]};
    text-align: center;
    box-shadow: 0 0 14px {threat_colors[threat_level]}40;
">
    <div style="
        font-size: 14px;
        color: #9CA3AF;
        margin-bottom: 8px;
        text-transform: uppercase;
        font-weight: 700;
    ">
        Threat Level
    </div>

    <div style="
        font-size: 30px;
        font-weight: 800;
        color: {threat_colors[threat_level]};
    ">
        {threat_level}
    </div>
</div>
"""
    )
st.divider()
top_left, top_right = st.columns([1.2, 1])

with top_left:
    st.header("Live SOC Alert Feed")

    if not alerts.empty:
        for _, row in alerts.sort_values("failed_attempts", ascending=False).iterrows():
            if row["severity"] == "Critical":
                st.error(f"🔥 CRITICAL | IP {row['source_ip']} → {row['username']} | {row['failed_attempts']} failed login attempts")
            elif row["severity"] == "High":
                st.error(f"🚨 HIGH | IP {row['source_ip']} → {row['username']} | {row['failed_attempts']} failed login attempts")
            elif row["severity"] == "Medium":
                st.warning(f"⚠️ MEDIUM | IP {row['source_ip']} → {row['username']} | {row['failed_attempts']} failed login attempts")
            else:
                st.info(f"ℹ️ LOW | IP {row['source_ip']} → {row['username']} | {row['failed_attempts']} failed login attempts")
    else:
        st.success("✅ No active SOC alerts.")

with top_right:
    st.header("Threat Summary")

    if not alerts.empty:
        most_active_ip = alerts.sort_values("failed_attempts", ascending=False).iloc[0]["source_ip"]
        highest_attempts = alerts["failed_attempts"].max()

        st.error("Potential brute-force activity detected.")
        st.write(f"**Threat Level:** `{threat_level}`")
        st.write(f"**Most Active Suspicious IP:** `{most_active_ip}`")
        st.write(f"**Highest Failed Attempts:** `{highest_attempts}`")
        st.write(
            f"**Detection Rule:** {brute_force_rule['rule_id']} — "
            f"{brute_force_rule['condition']}"
        )
    else:
        st.success("Environment currently appears stable.")
        st.write("No IP addresses have crossed the brute-force threshold.")

st.divider()

mid_left, mid_right = st.columns([1, 1])

with mid_left:
    st.header("Top Attacking IP Addresses")

    if not suspicious_ips.empty:
        st.bar_chart(suspicious_ips.set_index("source_ip")["failed_attempts"])
    else:
        st.info("No failed login attempts found.")

with mid_right:
    st.header("Global Security Event Map")

    map_filter = st.selectbox(
        "Map Filter",
        ["All Events", "Failed Logins Only", "Successful Logins Only"]
    )

    if map_filter == "Failed Logins Only":
        filtered_map_df = dashboard_df[dashboard_df["status"] == "failed"]
    elif map_filter == "Successful Logins Only":
        filtered_map_df = dashboard_df[dashboard_df["status"] == "success"]
    else:
        filtered_map_df = dashboard_df

    map_data = filtered_map_df.rename(columns={
        "latitude": "lat",
        "longitude": "lon"
    })

    map_data = map_data.dropna(
        subset=["lat", "lon"]
    ).head(500)

    st.map(
        map_data[["lat", "lon"]],
        size=8,
        zoom=0
    )

st.divider()

timeline_col, country_col = st.columns([1.2, 1])

with timeline_col:
    st.header("Authentication Timeline")

    timeline = (
        dashboard_df.set_index("event_time")
        .groupby("status")
        .resample("1min")
        .size()
        .reset_index(name="count")
    )

    if not timeline.empty:
        timeline_pivot = timeline.pivot(
            index="event_time",
            columns="status",
            values="count"
        ).fillna(0)

        st.line_chart(timeline_pivot)
    else:
        st.info("No timeline data available.")

with country_col:
    st.header("Attack Origin Analysis")

    top_countries = (
        failed_logins.groupby("geo_country")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values("failed_attempts", ascending=False)
    )

    if not top_countries.empty:
        st.dataframe(top_countries, width="stretch")
    else:
        st.success("No failed login countries to display.")

st.divider()

st.header("Impossible Travel Detection")

if not impossible_travel_df.empty:

    st.error("Potential impossible travel activity detected.")

    st.dataframe(
        impossible_travel_df,
        width="stretch"
    )

else:
    st.success("No impossible travel activity detected.")
st.divider()

feed_col, alert_col = st.columns([1.2, 1])


with feed_col:
    st.header("Recent Authentication Events")

    recent_events = dashboard_df.head(100)

    st.dataframe(
        recent_events,
        width="stretch",
        hide_index=True
    )

with alert_col:
    st.header("Suspicious IP Alert Table")

    if not alerts.empty:
        st.dataframe(alerts, width="stretch")
    else:
        st.success("No suspicious brute-force activity detected.")

st.divider()

st.header("Open Incidents")

if not incident_queue_df.empty:
    st.dataframe(
        incident_queue_df,
        width="stretch",
        hide_index=True
    )
else:
    st.success("No active incidents in the queue.")