import streamlit as st
import pandas as pd
from db import get_connection


@st.cache_data(ttl=30)
def load_data(hours=24):
    conn = get_connection()

    query = """
        SELECT
            event_id,
            event_time,
            source_ip,
            username,
            event_type,
            status,
            geo_country,
            device_type,
            latitude,
            longitude
        FROM events
        WHERE event_time >= NOW() - INTERVAL %s HOUR
        ORDER BY event_time DESC
    """

    df = pd.read_sql(
        query,
        conn,
        params=(hours,)
    )

    conn.close()

    df["event_time"] = pd.to_datetime(
        df["event_time"],
        errors="coerce"
    )

    df["latitude"] = pd.to_numeric(
        df["latitude"],
        errors="coerce"
    )

    df["longitude"] = pd.to_numeric(
        df["longitude"],
        errors="coerce"
    )

    return df


@st.cache_data(ttl=30)
def load_network_data(hours=24):
    """Firewall, VPN and flow events from network_events."""
    conn = get_connection()

    query = """
        SELECT
            id,
            event_time,
            event_source,
            action,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
            bytes_out,
            username,
            geo_country,
            device_name
        FROM network_events
        WHERE event_time >= NOW() - INTERVAL %s HOUR
        ORDER BY event_time DESC
    """

    df = pd.read_sql(query, conn, params=(hours,))
    conn.close()

    df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce")
    df["bytes_out"] = pd.to_numeric(df["bytes_out"], errors="coerce").fillna(0)

    return df


@st.cache_data(ttl=15)
def load_network_devices():
    conn = get_connection()

    df = pd.read_sql(
        """
        SELECT
            device_name,
            device_type,
            mgmt_ip,
            location,
            status,
            cpu_percent,
            bandwidth_mbps,
            capacity_mbps,
            interface_errors,
            last_seen
        FROM network_devices
        ORDER BY device_type, device_name
        """,
        conn,
    )

    conn.close()
    return df


@st.cache_data(ttl=30)
def load_events_between(start, end):
    """Authentication events in a specific time range (any age)."""
    conn = get_connection()

    df = pd.read_sql(
        """
        SELECT
            event_id, event_time, source_ip, username, event_type,
            status, geo_country, device_type, latitude, longitude
        FROM events
        WHERE event_time BETWEEN %s AND %s
        ORDER BY event_time DESC
        """,
        conn,
        params=(start, end),
    )

    conn.close()
    df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce")
    return df


@st.cache_data(ttl=30)
def load_network_events_between(start, end):
    """
    Network events in a time range, mapped onto the authentication
    event columns so incident pages can treat both the same way.
    """
    conn = get_connection()

    df = pd.read_sql(
        """
        SELECT
            id, event_time, event_source, action, src_ip, src_port,
            dst_ip, dst_port, protocol, bytes_out, username,
            geo_country, device_name
        FROM network_events
        WHERE event_time BETWEEN %s AND %s
        ORDER BY event_time DESC
        """,
        conn,
        params=(start, end),
    )

    conn.close()

    if df.empty:
        return pd.DataFrame(columns=[
            "event_id", "event_time", "source_ip", "username", "event_type",
            "status", "geo_country", "device_type", "dst_ip", "dst_port",
        ])

    df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce")

    mapped = pd.DataFrame({
        "event_id": df["id"],
        "event_time": df["event_time"],
        "source_ip": df["src_ip"],
        "username": df["username"],
        "event_type": df["event_source"] + "_" + df["action"],
        "status": df["action"].map(
            {"deny": "failed", "failed": "failed", "allow": "success", "success": "success"}
        ).fillna("unknown"),
        "geo_country": df["geo_country"].fillna("Internal"),
        "device_type": df["device_name"],
        "dst_ip": df["dst_ip"],
        "dst_port": df["dst_port"],
    })

    return mapped
