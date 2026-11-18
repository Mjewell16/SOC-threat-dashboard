import pandas as pd
from utils.detection_rules import DETECTION_RULES, mitre_label

def assign_severity(row):
    if row["failed_attempts"] >= 15:
        return "Critical"
    elif row["failed_attempts"] >= 10:
        return "High"
    elif row["failed_attempts"] >= 5:
        return "Medium"
    return "Low"


def get_threat_level(alert_count, failed_count):
    if alert_count >= 3 or failed_count >= 20:
        return "Critical"
    elif alert_count >= 2 or failed_count >= 10:
        return "High"
    elif alert_count >= 1 or failed_count >= 5:
        return "Medium"
    return "Low"


def detect_brute_force(df):
    rule = DETECTION_RULES["brute_force"]

    if df.empty:
        return pd.DataFrame()

    required_columns = {"event_time", "source_ip", "username", "status"}
    if not required_columns.issubset(df.columns):
        return pd.DataFrame()

    failed_df = df[df["status"] == "failed"].copy()
    if failed_df.empty:
        return pd.DataFrame()

    failed_df["event_time"] = pd.to_datetime(failed_df["event_time"])

    brute_force_summary = (
        failed_df.groupby(["source_ip", "username"])
        .agg(
            failed_attempts=("username", "size"),
            first_seen=("event_time", "min"),
            last_seen=("event_time", "max"),
        )
        .reset_index()
    )

    brute_force_alerts = brute_force_summary[
    brute_force_summary["failed_attempts"] >= rule["threshold"]
    ].copy()

    if brute_force_alerts.empty:
        return pd.DataFrame()

    brute_force_alerts["severity"] = brute_force_alerts.apply(assign_severity, axis=1)
    brute_force_alerts["incident_type"] = rule["incident_type"]

    brute_force_alerts["rule_id"] = rule["rule_id"]
    brute_force_alerts["mitre"] = mitre_label("brute_force")

    brute_force_alerts["mitre_tactic"] = rule["tactic"]
    brute_force_alerts["detection_summary"] = brute_force_alerts.apply(
        lambda row: (
            f"{int(row['failed_attempts'])} failed logins against {row['username']} "
            f"from {row['source_ip']}."
        ),
        axis=1,
    )

    return brute_force_alerts


def detect_password_spray(df):
    rule = DETECTION_RULES["password_spray"]

    if df.empty:
        return pd.DataFrame()

    required_columns = {"event_time", "source_ip", "username", "status"}
    if not required_columns.issubset(df.columns):
        return pd.DataFrame()

    failed_df = df[df["status"] == "failed"].copy()
    if failed_df.empty:
        return pd.DataFrame()

    failed_df["event_time"] = pd.to_datetime(failed_df["event_time"])

    spray_summary = (
        failed_df.groupby("source_ip")
        .agg(
            unique_users=("username", "nunique"),
            failed_attempts=("username", "size"),
            first_seen=("event_time", "min"),
            last_seen=("event_time", "max"),
        )
        .reset_index()
    )

    spray_alerts = spray_summary[spray_summary["unique_users"] >= rule["unique_user_threshold"]].copy()
    if spray_alerts.empty:
        return pd.DataFrame()

    spray_alerts["severity"] = rule["severity"]
    spray_alerts["incident_type"] = rule["incident_type"]
    spray_alerts["rule_id"] = rule["rule_id"]
    spray_alerts["mitre"] = mitre_label("password_spray")
    spray_alerts["mitre_tactic"] = rule["tactic"]
    spray_alerts["detection_summary"] = spray_alerts.apply(
        lambda row: (
            f"{int(row['failed_attempts'])} failed attempts across "
            f"{int(row['unique_users'])} users from {row['source_ip']}."
        ),
        axis=1,
    )

    return spray_alerts


def detect_account_takeover(df):
    rule = DETECTION_RULES["account_takeover"]

    if df.empty:
        return pd.DataFrame()

    required_columns = {"event_time", "source_ip", "username", "status"}
    if not required_columns.issubset(df.columns):
        return pd.DataFrame()

    working_df = df.copy()
    working_df["event_time"] = pd.to_datetime(working_df["event_time"])
    working_df = working_df.sort_values("event_time")

    takeover_alerts = []

    for (username, source_ip), group in working_df.groupby(["username", "source_ip"]):
        group = group.sort_values("event_time")
        success_events = group[group["status"] == "success"]

        if success_events.empty:
            continue

        for _, success_row in success_events.iterrows():
            previous_failures = group[
                (group["status"] == "failed")
                & (group["event_time"] < success_row["event_time"])
            ]

            if len(previous_failures) >= rule["failure_threshold"]:
                takeover_alerts.append(
                    {
                        "username": username,
                        "source_ip": source_ip,
                        "failed_attempts": len(previous_failures),
                        "successful_login": success_row["event_time"],
                        "severity": rule["severity"],
                        "incident_type": rule["incident_type"],
                        "rule_id": rule["rule_id"],
                        "mitre": mitre_label("account_takeover"),
                        "mitre_tactic": rule["tactic"],
                        "detection_summary": (
                            f"{len(previous_failures)} failed logins were followed by a successful "
                            f"login for {username} from {source_ip}."
                        ),
                    }
                )
                break

    return pd.DataFrame(takeover_alerts)
