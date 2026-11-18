"""
AEGIS network detections.

Each function takes a DataFrame of network_events (already limited to the
detection window by the calling page) and returns one row per alert.
Thresholds come from utils/detection_rules.py.
"""

import ipaddress

import pandas as pd

from utils.detection_rules import DETECTION_RULES, mitre_label


# RFC 1918 private ranges. Python's is_private also flags the TEST-NET
# documentation ranges (192.0.2.0/24 etc.), which the simulator uses as
# "external" attacker infrastructure, so internal space is defined here.
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_internal(ip):
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return False

    return any(address in network for network in INTERNAL_NETWORKS)


def _has_columns(df, columns):
    return not df.empty and set(columns).issubset(df.columns)


# =========================================================
# AEGIS-005 — PORT SCAN (T1046)
# One source probing many ports or many hosts
# =========================================================

def detect_port_scan(df):
    rule = DETECTION_RULES["port_scan"]

    if not _has_columns(df, {"event_source", "src_ip", "dst_ip", "dst_port", "event_time"}):
        return pd.DataFrame()

    fw = df[df["event_source"] == "firewall"].copy()
    if fw.empty:
        return pd.DataFrame()

    summary = (
        fw.groupby("src_ip")
        .agg(
            unique_ports=("dst_port", "nunique"),
            unique_hosts=("dst_ip", "nunique"),
            connection_attempts=("dst_port", "size"),
            denied=("action", lambda s: int((s == "deny").sum())),
            first_seen=("event_time", "min"),
            last_seen=("event_time", "max"),
        )
        .reset_index()
    )

    alerts = summary[
        (summary["unique_ports"] >= rule["unique_port_threshold"])
        | (summary["unique_hosts"] >= rule["unique_host_threshold"])
    ].copy()

    if alerts.empty:
        return pd.DataFrame()

    alerts["severity"] = alerts["unique_ports"].apply(
        lambda ports: "High" if ports >= rule["unique_port_threshold"] * 2 else "Medium"
    )
    alerts["incident_type"] = rule["incident_type"]
    alerts["rule_id"] = rule["rule_id"]
    alerts["mitre"] = mitre_label("port_scan")
    alerts["mitre_tactic"] = rule["tactic"]
    alerts["detection_summary"] = alerts.apply(
        lambda row: (
            f"{row['src_ip']} probed {int(row['unique_ports'])} ports across "
            f"{int(row['unique_hosts'])} hosts ({int(row['denied'])} denied by firewall)."
        ),
        axis=1,
    )

    return alerts


# =========================================================
# AEGIS-006 — VPN BRUTE FORCE (T1133)
# Repeated failed VPN logins for one account from one source
# =========================================================

def detect_vpn_brute_force(df):
    rule = DETECTION_RULES["vpn_brute_force"]

    if not _has_columns(df, {"event_source", "action", "src_ip", "username", "event_time"}):
        return pd.DataFrame()

    vpn = df[df["event_source"] == "vpn"].copy()
    if vpn.empty:
        return pd.DataFrame()

    failed = vpn[vpn["action"] == "failed"]
    if failed.empty:
        return pd.DataFrame()

    summary = (
        failed.groupby(["src_ip", "username"])
        .agg(
            failed_attempts=("username", "size"),
            geo_country=("geo_country", "first"),
            first_seen=("event_time", "min"),
            last_seen=("event_time", "max"),
        )
        .reset_index()
    )

    alerts = summary[summary["failed_attempts"] >= rule["threshold"]].copy()
    if alerts.empty:
        return pd.DataFrame()

    # Escalate if the same source later logged in successfully
    successes = vpn[vpn["action"] == "success"][["src_ip", "username", "event_time"]]

    def followed_by_success(row):
        match = successes[
            (successes["src_ip"] == row["src_ip"])
            & (successes["username"] == row["username"])
            & (successes["event_time"] > row["first_seen"])
        ]
        return not match.empty

    alerts["vpn_session_established"] = alerts.apply(followed_by_success, axis=1)
    alerts["severity"] = alerts["vpn_session_established"].map(
        {True: "Critical", False: "High"}
    )
    alerts["incident_type"] = rule["incident_type"]
    alerts["rule_id"] = rule["rule_id"]
    alerts["mitre"] = mitre_label("vpn_brute_force")
    alerts["mitre_tactic"] = rule["tactic"]
    alerts["detection_summary"] = alerts.apply(
        lambda row: (
            f"{int(row['failed_attempts'])} failed VPN logins for {row['username']} "
            f"from {row['src_ip']} ({row['geo_country']})"
            + (" — followed by a successful VPN session." if row["vpn_session_established"] else ".")
        ),
        axis=1,
    )

    return alerts


# =========================================================
# AEGIS-007 — BEACONING (T1071)
# Internal host contacting the same external destination at
# regular intervals (low jitter), like malware check-ins
# =========================================================

def detect_beaconing(df):
    rule = DETECTION_RULES["beaconing"]

    if not _has_columns(df, {"event_source", "src_ip", "dst_ip", "dst_port", "event_time"}):
        return pd.DataFrame()

    flows = df[df["event_source"] == "flow"].copy()
    if flows.empty:
        return pd.DataFrame()

    flows = flows[
        flows["src_ip"].apply(is_internal)
        & ~flows["dst_ip"].apply(is_internal)
    ]
    if flows.empty:
        return pd.DataFrame()

    alerts = []

    for (src, dst, port), group in flows.groupby(["src_ip", "dst_ip", "dst_port"]):
        if len(group) < rule["min_connections"]:
            continue

        times = group["event_time"].sort_values()
        intervals = times.diff().dt.total_seconds().dropna()

        mean_interval = intervals.mean()
        if mean_interval <= 0:
            continue

        # Coefficient of variation: low value = machine-like regularity
        jitter = intervals.std() / mean_interval

        if jitter <= rule["max_jitter"]:
            alerts.append({
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": int(port),
                "connections": len(group),
                "avg_interval_sec": round(mean_interval, 1),
                "jitter": round(jitter, 3),
                "bytes_out": int(group["bytes_out"].sum()),
                "first_seen": times.min(),
                "last_seen": times.max(),
                "severity": rule["severity"],
                "incident_type": rule["incident_type"],
                "rule_id": rule["rule_id"],
                "mitre": mitre_label("beaconing"),
                "mitre_tactic": rule["tactic"],
                "detection_summary": (
                    f"{src} contacted {dst}:{int(port)} {len(group)} times "
                    f"every ~{round(mean_interval)}s (jitter {round(jitter * 100, 1)}%)."
                ),
            })

    return pd.DataFrame(alerts)


def run_network_detections(df):
    """Run all network detections. Returns a dict of DataFrames."""
    return {
        "port_scan": detect_port_scan(df),
        "vpn_brute_force": detect_vpn_brute_force(df),
        "beaconing": detect_beaconing(df),
    }
