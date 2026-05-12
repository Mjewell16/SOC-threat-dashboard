import streamlit as st
import pandas as pd
from pathlib import Path
from streamlit_autorefresh import st_autorefresh
from datetime import datetime

st.set_page_config(
    page_title="SOC Command Center",
    page_icon="🛡️",
    layout="wide"
)

st_autorefresh(interval=5000, key="aegis_refresh")

CSV_PATH = Path("data/security_events.csv")

st.markdown("""
<style>

/* MAIN BACKGROUND */
.stApp {
    background-color: #0A0F14;
    color: #E5E7EB;
}

/* MAIN CONTAINER */
.block-container {
    padding-top: 1.5rem;
    padding-bottom: 2rem;
    max-width: 96%;
}

/* HEADERS */
h1 {
    color: #00F5D4;
    font-weight: 800;
    letter-spacing: 1px;
    text-transform: uppercase;
}

h2, h3 {
    color: #D1D5DB;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

/* METRIC CARDS */
[data-testid="stMetric"] {
    background: linear-gradient(
        145deg,
        rgba(16,24,32,0.95),
        rgba(20,30,40,0.95)
    );
    border: 1px solid rgba(0,255,200,0.18);
    padding: 18px;
    border-radius: 16px;
    box-shadow:
        0 0 10px rgba(0,255,200,0.05),
        0 6px 18px rgba(0,0,0,0.45);
    transition: all 0.25s ease;
}

/* METRIC HOVER */
[data-testid="stMetric"]:hover {
    transform: translateY(-4px);
    border: 1px solid rgba(0,255,200,0.4);
    box-shadow:
        0 0 16px rgba(0,255,200,0.12),
        0 10px 24px rgba(0,0,0,0.55);
}

/* METRIC VALUES */
[data-testid="stMetricValue"] {
    color: #00F5D4;
    font-size: 30px;
    font-weight: 700;
}

/* ALERT BOXES */
[data-testid="stAlert"] {
    border-radius: 12px;
    border: 1px solid rgba(255,255,255,0.08);
    box-shadow: 0 4px 14px rgba(0,0,0,0.4);
}

/* DATA TABLES */
[data-testid="stDataFrame"] {
    background-color: rgba(15,23,32,0.96);
    border-radius: 14px;
    padding: 10px;
    border: 1px solid rgba(0,255,200,0.08);
    box-shadow: 0 6px 18px rgba(0,0,0,0.4);
}

/* CHARTS */
.element-container:has(canvas) {
    background-color: rgba(15,23,32,0.95);
    border-radius: 16px;
    padding: 16px;
    border: 1px solid rgba(0,255,200,0.08);
    box-shadow: 0 8px 20px rgba(0,0,0,0.45);
    transition: all 0.25s ease;
}

.element-container:has(canvas):hover {
    transform: translateY(-3px);
    box-shadow:
        0 0 14px rgba(0,255,200,0.08),
        0 10px 22px rgba(0,0,0,0.55);
}

/* MAP */
[data-testid="stDeckGlJsonChart"] {
    border-radius: 1px;
    overflow: hidden;
    border: 8px solid rgba(0,255,200,0.08);
    box-shadow: 0 8px 20px rgba(0,0,0,0.45);
}

/* SIDEBAR */
section[data-testid="stSidebar"] {
    background-color: #111827;
    border-right: 1px solid rgba(0,255,200,0.08);
}

/* DIVIDERS */
hr {
    border: none;
    border-top: 1px solid rgba(0,255,200,0.1);
    margin-top: 1.2rem;
    margin-bottom: 1.2rem;
}

/* SCROLLBAR */
::-webkit-scrollbar {
    width: 10px;
}

::-webkit-scrollbar-track {
    background: #0F172A;
}

::-webkit-scrollbar-thumb {
    background: rgba(0,255,200,0.3);
    border-radius: 10px;
}

::-webkit-scrollbar-thumb:hover {
    background: rgba(0,255,200,0.5);
}

</style>
""", unsafe_allow_html=True)

def load_data():
    df = pd.read_csv(CSV_PATH)
    df["event_time"] = pd.to_datetime(df["event_time"])
    return df

def assign_severity(row):
    if row["failed_attempts"] >= 15:
        return "Critical"
    elif row["failed_attempts"] >= 10:
        return "High"
    elif row["failed_attempts"] >= 5:
        return "Medium"
    else:
        return "Low"

def get_threat_level(alert_count, failed_count):
    if alert_count >= 3 or failed_count >= 20:
        return "Critical"
    elif alert_count >= 2 or failed_count >= 10:
        return "High"
    elif alert_count >= 1 or failed_count >= 5:
        return "Medium"
    else:
        return "Low"



df = load_data()

# Rolling activity window (15 minutes)
recent_cutoff = pd.Timestamp.now() - pd.Timedelta(minutes=15)

recent_df = df[
    df["event_time"] >= recent_cutoff
]

total_events = len(df)
failed_logins = recent_df[recent_df["status"] == "failed"]
successful_logins = recent_df[recent_df["status"] == "success"]

suspicious_ips = (
    failed_logins.groupby("source_ip")
    .size()
    .reset_index(name="failed_attempts")
)

if not suspicious_ips.empty:
    suspicious_ips["severity"] = suspicious_ips.apply(assign_severity, axis=1)
else:
    suspicious_ips["severity"] = []

alerts = suspicious_ips[suspicious_ips["failed_attempts"] >= 5]

# User authentication analytics
user_login_summary = (
    df.groupby("username")
    .agg({
        "event_time": ["min", "max"],
        "source_ip": "nunique",
        "geo_country": "nunique"
    })
)

user_login_summary.columns = [
    "first_seen",
    "last_seen",
    "unique_ips",
    "unique_countries"
]

# Impossible travel detection
impossible_travel_alerts = []

for username in df["username"].unique():

    user_events = (
        df[df["username"] == username]
        .sort_values("event_time")
    )

    previous_country = None
    previous_time = None

    for _, row in user_events.iterrows():

        current_country = row["geo_country"]
        current_time = row["event_time"]

        if previous_country is not None:

            time_difference = (
                current_time - previous_time
            ).total_seconds() / 60

            if (
                current_country != previous_country
                and time_difference < 60
            ):

                impossible_travel_alerts.append({
                    "username": username,
                    "from_country": previous_country,
                    "to_country": current_country,
                    "minutes_between": round(time_difference, 2)
                })

        previous_country = current_country
        previous_time = current_time

impossible_travel_df = pd.DataFrame(impossible_travel_alerts)

user_login_summary = user_login_summary.reset_index()

threat_level = get_threat_level(len(alerts), len(failed_logins))

threat_colors = {
    "Low": "#00FF99",
    "Medium": "#FFD166",
    "High": "#FF8C42",
    "Critical": "#FF3B3B"
}

st.title("SOC Command Center")
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

col1.metric("Total Events", total_events)
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
                st.error(f"🔥 CRITICAL | IP {row['source_ip']} | {row['failed_attempts']} failed login attempts")
            elif row["severity"] == "High":
                st.error(f"🚨 HIGH | IP {row['source_ip']} | {row['failed_attempts']} failed login attempts")
            elif row["severity"] == "Medium":
                st.warning(f"⚠️ MEDIUM | IP {row['source_ip']} | {row['failed_attempts']} failed login attempts")
            else:
                st.info(f"ℹ️ LOW | IP {row['source_ip']} | {row['failed_attempts']} failed login attempts")
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
        st.write("**Detection Rule:** 5+ failed logins from same IP")
    else:
        st.success("Environment currently appears stable.")
        st.write("No IP addresses have crossed the brute-force threshold.")

st.divider()

mid_left, mid_right = st.columns([1, 1])

with mid_left:
    st.header("Failed Login Attempts by Source IP")

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
        filtered_map_df = df[df["status"] == "failed"]
    elif map_filter == "Successful Logins Only":
        filtered_map_df = df[df["status"] == "success"]
    else:
        filtered_map_df = df

    map_data = filtered_map_df.rename(columns={
        "latitude": "lat",
        "longitude": "lon"
    })

    st.map(map_data[["lat", "lon"]], size=8, zoom=0)

st.divider()

timeline_col, country_col = st.columns([1.2, 1])

with timeline_col:
    st.header("Authentication Timeline")

    timeline = (
        df.set_index("event_time")
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
    st.header("Top Countries by Failed Logins")

    top_countries = (
        failed_logins.groupby("geo_country")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values("failed_attempts", ascending=False)
    )

    if not top_countries.empty:
        st.dataframe(top_countries, use_container_width=True)
    else:
        st.success("No failed login countries to display.")

st.divider()

st.header("Impossible Travel Detection")

if not impossible_travel_df.empty:

    st.error("Potential impossible travel activity detected.")

    st.dataframe(
        impossible_travel_df,
        use_container_width=True
    )

else:
    st.success("No impossible travel activity detected.")
st.divider()

feed_col, alert_col = st.columns([1.2, 1])


with feed_col:
    st.header("Recent Authentication Events")

    recent_events = df.sort_values("event_time", ascending=False).head(10)
    st.dataframe(recent_events, use_container_width=True)

with alert_col:
    st.header("Suspicious IP Alert Table")

    if not alerts.empty:
        st.dataframe(alerts, use_container_width=True)
    else:
        st.success("No suspicious brute-force activity detected.")

st.divider()

st.header("Security Event Logs")
st.dataframe(df.sort_values("event_time", ascending=False), use_container_width=True)