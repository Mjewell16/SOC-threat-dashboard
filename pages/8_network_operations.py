import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from utils.styles import load_styles
from utils.data_loader import load_network_data, load_network_devices
from utils.detection_rules import DETECTION_RULES, DETECTION_WINDOW_MINUTES
from utils.network_detections import is_internal, run_network_detections
from utils.network_simulations import refresh_device_telemetry


st_autorefresh(interval=120000, key="netops_refresh")

load_styles()

st.title("Network Operations")
st.caption(
    "Infrastructure health, traffic visibility, and network threat "
    "detection across firewall, VPN, and flow telemetry."
)


# =========================================================
# LOAD DATA
# =========================================================

net_df = load_network_data()
devices = load_network_devices()

recent_cutoff = pd.Timestamp.now() - pd.Timedelta(minutes=DETECTION_WINDOW_MINUTES)
recent_net = net_df[net_df["event_time"] >= recent_cutoff].copy()

detections = run_network_detections(recent_net)
total_detections = sum(len(d) for d in detections.values())


# =========================================================
# TOP METRICS
# =========================================================

devices_up = int((devices["status"] == "Up").sum()) if not devices.empty else 0
devices_down = int((devices["status"] != "Up").sum()) if not devices.empty else 0

firewall_recent = recent_net[recent_net["event_source"] == "firewall"]
denied_recent = int((firewall_recent["action"] == "deny").sum())

vpn_recent = recent_net[recent_net["event_source"] == "vpn"]
vpn_failed = int((vpn_recent["action"] == "failed").sum())

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Devices Up", f"{devices_up}/{len(devices)}")
col2.metric("Devices Down", devices_down)
col3.metric(f"Firewall Denies ({DETECTION_WINDOW_MINUTES}m)", denied_recent)
col4.metric(f"VPN Failures ({DETECTION_WINDOW_MINUTES}m)", vpn_failed)
col5.metric("Network Detections", total_detections)

if devices_down:
    down_names = ", ".join(devices[devices["status"] != "Up"]["device_name"])
    st.error(f"Device outage: {down_names} not responding.")


# =========================================================
# INFRASTRUCTURE HEALTH
# =========================================================

st.divider()

health_header, health_button = st.columns([4, 1])

with health_header:
    st.header("Infrastructure Health")

with health_button:
    if st.button("Poll Devices", icon=":material/refresh:", width="stretch"):
        refresh_device_telemetry()
        st.cache_data.clear()
        st.rerun()

if devices.empty:
    st.info("No network devices found. Run sql/network_schema.sql to load the inventory.")
else:
    device_view = devices.copy()
    device_view["utilization"] = (
        device_view["bandwidth_mbps"] / device_view["capacity_mbps"] * 100
    ).round(0)

    st.dataframe(
        device_view[[
            "status", "device_name", "device_type", "mgmt_ip", "location",
            "cpu_percent", "utilization", "bandwidth_mbps", "interface_errors",
            "last_seen",
        ]],
        hide_index=True,
        width="stretch",
        column_config={
            "status": "Status",
            "device_name": "Device",
            "device_type": "Type",
            "mgmt_ip": "Mgmt IP",
            "location": "Location",
            "cpu_percent": st.column_config.ProgressColumn(
                "CPU", format="%d%%", min_value=0, max_value=100
            ),
            "utilization": st.column_config.ProgressColumn(
                "Link Utilization", format="%d%%", min_value=0, max_value=100
            ),
            "bandwidth_mbps": st.column_config.NumberColumn("Throughput", format="%d Mbps"),
            "interface_errors": "Interface Errors",
            "last_seen": st.column_config.DatetimeColumn("Last Seen", format="MM/DD hh:mm a"),
        },
    )


# =========================================================
# NETWORK THREAT DETECTIONS
# =========================================================

st.divider()
st.header("Network Threat Detections")

det_cols = st.columns(3)

for col, key in zip(det_cols, ["port_scan", "vpn_brute_force", "beaconing"]):
    rule = DETECTION_RULES[key]
    col.metric(f"{rule['rule_id']} · {rule['name']}", len(detections[key]))

detection_views = {
    "port_scan": ["severity", "src_ip", "unique_ports", "unique_hosts", "denied", "mitre", "detection_summary"],
    "vpn_brute_force": ["severity", "src_ip", "username", "geo_country", "failed_attempts", "vpn_session_established", "mitre", "detection_summary"],
    "beaconing": ["severity", "src_ip", "dst_ip", "dst_port", "connections", "avg_interval_sec", "jitter", "mitre", "detection_summary"],
}

any_detection = False

for key, columns in detection_views.items():
    alerts = detections[key]
    if alerts.empty:
        continue

    any_detection = True
    rule = DETECTION_RULES[key]

    st.subheader(f"{rule['name']} — {rule['mitre']} {rule['mitre_name']}")
    st.dataframe(alerts[columns], hide_index=True, width="stretch")

if not any_detection:
    st.success(
        f"No network threats detected in the last {DETECTION_WINDOW_MINUTES} minutes."
    )


# =========================================================
# TRAFFIC VISIBILITY
# =========================================================

st.divider()
st.header("Traffic Visibility")

if net_df.empty:
    st.info("No network telemetry yet. Generate traffic from the Attack Simulation page.")
else:
    talkers_col, ports_col = st.columns(2)

    with talkers_col:
        st.subheader("Top Talkers (24h)")

        flows = net_df[net_df["event_source"] == "flow"]
        internal_flows = flows[flows["src_ip"].apply(is_internal)]

        if internal_flows.empty:
            st.info("No outbound flow data.")
        else:
            top_talkers = (
                internal_flows.groupby("src_ip")["bytes_out"]
                .sum()
                .div(1_000_000)
                .round(2)
                .sort_values(ascending=False)
                .head(10)
                .rename("MB Out")
            )
            st.bar_chart(top_talkers, horizontal=True)

    with ports_col:
        st.subheader("Firewall Denies by Port (24h)")

        denies = net_df[
            (net_df["event_source"] == "firewall") & (net_df["action"] == "deny")
        ]

        if denies.empty:
            st.success("No denied connections.")
        else:
            by_port = (
                denies.groupby("dst_port")
                .size()
                .sort_values(ascending=False)
                .head(15)
                .rename("Denied")
            )
            by_port.index = by_port.index.map(lambda p: f"{int(p)}")
            st.bar_chart(by_port)

    st.subheader("Traffic Timeline (24h)")

    timeline = (
        net_df.set_index("event_time")
        .groupby("event_source")
        .resample("5min")
        .size()
        .reset_index(name="events")
        .pivot(index="event_time", columns="event_source", values="events")
        .fillna(0)
    )
    st.line_chart(timeline)

    st.subheader("Recent Network Events")
    st.dataframe(net_df.head(200), hide_index=True, width="stretch")
