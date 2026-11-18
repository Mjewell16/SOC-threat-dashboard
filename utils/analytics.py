import math

import pandas as pd

from utils.detection_rules import DETECTION_RULES, mitre_label


EARTH_RADIUS_KM = 6371.0


def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two points on Earth, in kilometers."""
    lat1, lon1, lat2, lon2 = map(math.radians, (lat1, lon1, lat2, lon2))

    a = (
        math.sin((lat2 - lat1) / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    )

    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def detect_impossible_travel(df):
    """
    Detect consecutive successful logins for the same user from locations
    too far apart to physically travel between in the time elapsed.

    Uses the haversine distance between login coordinates and flags any
    pair that would require travelling faster than a commercial airliner.

    MITRE ATT&CK:
        T1078 - Valid Accounts
    """

    rule = DETECTION_RULES["impossible_travel"]
    max_speed = rule["max_speed_kmh"]
    min_distance = rule["min_distance_km"]

    if df.empty:
        return pd.DataFrame()

    required_columns = {
        "username",
        "event_time",
        "geo_country",
        "source_ip",
        "status",
        "latitude",
        "longitude",
    }

    if not required_columns.issubset(df.columns):
        return pd.DataFrame()

    successful_logins = df[
        (df["status"] == "success")
        & df["latitude"].notna()
        & df["longitude"].notna()
    ].copy()

    if successful_logins.empty:
        return pd.DataFrame()

    successful_logins["event_time"] = pd.to_datetime(
        successful_logins["event_time"]
    )

    alerts = []

    for username, user_events in successful_logins.groupby("username"):

        user_events = user_events.sort_values("event_time")
        previous = None

        for _, current in user_events.iterrows():

            if previous is not None:

                distance_km = haversine_km(
                    float(previous["latitude"]),
                    float(previous["longitude"]),
                    float(current["latitude"]),
                    float(current["longitude"]),
                )

                raw_hours = (
                    current["event_time"] - previous["event_time"]
                ).total_seconds() / 3600

                # Logins in the same second: treat as one minute apart
                # so speed is finite but still clearly impossible.
                hours = max(raw_hours, 1 / 60)

                speed_kmh = distance_km / hours

                if distance_km >= min_distance and speed_kmh > max_speed:

                    minutes = round(raw_hours * 60, 1)
                    time_text = (
                        "under 1 minute apart"
                        if raw_hours < 1 / 60
                        else f"{minutes} minutes apart"
                    )

                    alerts.append({
                        "username": username,
                        "from_country": previous["geo_country"],
                        "to_country": current["geo_country"],
                        "from_ip": previous["source_ip"],
                        "to_ip": current["source_ip"],
                        "distance_km": round(distance_km),
                        "minutes_between": minutes,
                        "required_speed_kmh": round(speed_kmh),
                        "severity": rule["severity"],
                        "incident_type": rule["incident_type"],
                        "rule_id": rule["rule_id"],
                        "mitre": mitre_label("impossible_travel"),
                        "mitre_tactic": rule["tactic"],
                        "detection_summary": (
                            f"{username} logged in from {previous['geo_country']} and "
                            f"{current['geo_country']} ({round(distance_km):,} km apart) "
                            f"{time_text} — requires "
                            f"{round(speed_kmh):,} km/h."
                        ),
                    })

            previous = current

    return pd.DataFrame(alerts)
