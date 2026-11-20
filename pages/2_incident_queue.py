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
from utils.detection_rules import DETECTION_WINDOW_MINUTES
from utils.data_loader import load_network_data
from utils.network_detections import run_network_detections

from utils.incidents import (
    create_incident,
    get_incidents,
    update_incident_status,
    assign_incident,
)


load_styles()

st.title("Incident Queue")
st.caption(
    "SOC case management view for active security incidents."
)


# =========================================================
# LOAD AUTHENTICATION DATA
# =========================================================

df = load_data()

recent_cutoff = (
    pd.Timestamp.now()
    - pd.Timedelta(minutes=DETECTION_WINDOW_MINUTES)
)

recent_df = df[
    df["event_time"] >= recent_cutoff
].copy()


# =========================================================
# AEGIS-001 — BRUTE FORCE
# Same IP + same username (thresholds in utils/detection_rules.py)
# =========================================================

brute_force_alerts = detect_brute_force(recent_df)


# =========================================================
# AEGIS-004 — IMPOSSIBLE TRAVEL
# =========================================================

impossible_travel_alerts = (
    detect_impossible_travel(
        recent_df
    )
)


# =========================================================
# AEGIS-002 — PASSWORD SPRAY
# =========================================================

password_spray_alerts = (
    detect_password_spray(
        recent_df
    )
)

# =========================================================
# AEGIS-003 — ACCOUNT TAKEOVER
# =========================================================

account_takeover_alerts = (
    detect_account_takeover(
        recent_df
    )
)


# =========================================================
# CREATE BRUTE FORCE INCIDENTS
# =========================================================

for _, row in brute_force_alerts.iterrows():
    create_incident(
        severity=row["severity"],
        incident_type=row["incident_type"],
        source_ip=row["source_ip"],
        username=row["username"],
        failed_attempts=row["failed_attempts"],
        mitre=row["mitre"],
    )


# =========================================================
# CREATE IMPOSSIBLE TRAVEL INCIDENTS
# =========================================================

if not impossible_travel_alerts.empty:

    for _, row in impossible_travel_alerts.iterrows():

        create_incident(
            severity=row["severity"],
            incident_type="Impossible Travel",
            source_ip=row["to_ip"],
            username=row["username"],
            failed_attempts=0,
            mitre=row["mitre"],
        )


# =========================================================
# CREATE PASSWORD SPRAY INCIDENTS
# =========================================================

if not password_spray_alerts.empty:

    for _, row in password_spray_alerts.iterrows():

        create_incident(
            severity=row["severity"],
            incident_type="Password Spray",
            source_ip=row["source_ip"],
            username=None,
            failed_attempts=row["failed_attempts"],
            mitre=row["mitre"],
        )


# =========================================================
# CREATE ACCOUNT TAKEOVER INCIDENTS
# =========================================================

if not account_takeover_alerts.empty:

    for _, row in account_takeover_alerts.iterrows():

        create_incident(
            severity=row["severity"],
            incident_type="Potential Account Takeover",
            source_ip=row["source_ip"],
            username=row["username"],
            failed_attempts=row["failed_attempts"],
            mitre=row["mitre"],
        )


# =========================================================
# NETWORK DETECTIONS (AEGIS-005 to AEGIS-007)
# =========================================================

net_df = load_network_data()

recent_net = net_df[
    net_df["event_time"] >= recent_cutoff
].copy()

network_alerts = run_network_detections(recent_net)

for _, row in network_alerts["port_scan"].iterrows():
    create_incident(
        severity=row["severity"],
        incident_type=row["incident_type"],
        source_ip=row["src_ip"],
        username=None,
        failed_attempts=row["connection_attempts"],
        mitre=row["mitre"],
    )

for _, row in network_alerts["vpn_brute_force"].iterrows():
    create_incident(
        severity=row["severity"],
        incident_type=row["incident_type"],
        source_ip=row["src_ip"],
        username=row["username"],
        failed_attempts=row["failed_attempts"],
        mitre=row["mitre"],
    )

for _, row in network_alerts["beaconing"].iterrows():
    create_incident(
        severity=row["severity"],
        incident_type=row["incident_type"],
        source_ip=row["src_ip"],
        username=None,
        failed_attempts=row["connections"],
        mitre=row["mitre"],
    )

network_detection_count = sum(
    len(alerts) for alerts in network_alerts.values()
)


# =========================================================
# ACTIVE DETECTION COUNT
# =========================================================

active_detection_count = (
    len(brute_force_alerts)
    + len(impossible_travel_alerts)
    + len(password_spray_alerts)
    + len(account_takeover_alerts)
    + network_detection_count
)


# =========================================================
# LOAD PERSISTENT INCIDENTS
# =========================================================

incident_queue_df = get_incidents()

incident_queue_df = (
    incident_queue_df.rename(
        columns={
            "incident_id": "Incident ID",
            "created_at": "Created At",
            "severity": "Severity",
            "incident_type": "Incident Type",
            "source_ip": "Source IP",
            "username": "Username",
            "failed_attempts": "Failed Attempts",
            "status": "Status",
            "assigned_to": "Assigned To",
            "mitre_technique": "MITRE",
            "updated_at": "Updated At",
        }
    )
)


# =========================================================
# METRICS
# =========================================================

if not incident_queue_df.empty:

    open_incidents = (
        incident_queue_df[
            incident_queue_df["Status"] != "Closed"
        ]
    )

    critical_incidents = (
        incident_queue_df[
            incident_queue_df["Severity"] == "Critical"
        ]
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Incidents",
        len(incident_queue_df)
    )

    col2.metric(
        "Open Incidents",
        len(open_incidents)
    )

    col3.metric(
        "Critical",
        len(critical_incidents)
    )

    col4.metric(
        "Active Detections (15m)",
        active_detection_count
    )


    # =====================================================
    # DETECTION SUMMARY
    # =====================================================

    st.divider()

    st.subheader("Detection Summary")

    det1, det2, det3, det4 = st.columns(4)

    det1.metric(
        "Brute Force",
        len(brute_force_alerts)
    )

    det2.metric(
        "Impossible Travel",
        len(impossible_travel_alerts)
    )

    det3.metric(
        "Password Spray",
        len(password_spray_alerts)
    )

    det4.metric(
        "Account Takeover",
        len(account_takeover_alerts)
    )

    net_det1, net_det2, net_det3, _ = st.columns(4)

    net_det1.metric(
        "Port Scan",
        len(network_alerts["port_scan"])
    )

    net_det2.metric(
        "VPN Brute Force",
        len(network_alerts["vpn_brute_force"])
    )

    net_det3.metric(
        "C2 Beaconing",
        len(network_alerts["beaconing"])
    )


    # =====================================================
    # INCIDENT TABLE
    # =====================================================

    st.divider()

    st.subheader("Active Incident Queue")

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:

        status_filter = st.multiselect(
            "Status",
            [
                "Open",
                "Investigating",
                "Contained",
                "Closed",
            ],
            default=[
                "Open",
                "Investigating",
                "Contained",
            ]
        )

    with filter_col2:

        available_types = sorted(
            incident_queue_df[
                "Incident Type"
            ]
            .dropna()
            .unique()
            .tolist()
        )

        type_filter = st.multiselect(
            "Incident Type",
            available_types,
            default=available_types
        )


    filtered_incidents = (
        incident_queue_df[
            incident_queue_df[
                "Status"
            ].isin(status_filter)
            &
            incident_queue_df[
                "Incident Type"
            ].isin(type_filter)
        ]
    )


    st.dataframe(
        filtered_incidents,
        width="stretch",
        hide_index=True
    )


    # =====================================================
    # INCIDENT TRIAGE
    # =====================================================

    st.divider()

    st.subheader("Incident Triage")

    selected_incident = st.selectbox(
        "Select Incident",
        incident_queue_df[
            "Incident ID"
        ].tolist()
    )


    selected_row = (
        incident_queue_df[
            incident_queue_df[
                "Incident ID"
            ] == selected_incident
        ].iloc[0]
    )


    details_col, action_col = st.columns(2)


    # =====================================================
    # INCIDENT DETAILS
    # =====================================================

    with details_col:

        st.write(
            f"**Severity:** "
            f"{selected_row['Severity']}"
        )

        st.write(
            f"**Type:** "
            f"{selected_row['Incident Type']}"
        )

        st.write(
            f"**Source IP:** "
            f"`{selected_row['Source IP']}`"
        )

        username_value = (
            selected_row["Username"]
        )

        if pd.isna(username_value):
            username_value = "Multiple / Unknown"

        st.write(
            f"**Username:** "
            f"`{username_value}`"
        )

        st.write(
            f"**MITRE ATT&CK:** "
            f"{selected_row['MITRE']}"
        )

        st.write(
            f"**Failed Attempts:** "
            f"{selected_row['Failed Attempts']}"
        )

        st.write(
            f"**Created At:** "
            f"{selected_row['Created At']}"
        )


    # =====================================================
    # ANALYST ACTIONS
    # =====================================================

    with action_col:

        status_options = [
            "Open",
            "Investigating",
            "Contained",
            "Closed",
        ]

        current_status = (
            selected_row["Status"]
        )

        if current_status not in status_options:
            current_status = "Open"


        new_status = st.selectbox(
            "Incident Status",
            status_options,
            index=status_options.index(
                current_status
            )
        )


        current_analyst = (
            selected_row["Assigned To"]
        )

        if pd.isna(current_analyst):
            current_analyst = "Unassigned"


        analyst = st.text_input(
            "Assigned Analyst",
            value=str(
                current_analyst
            )
        )

        # =====================================================
        # INVESTIGATE INCIDENT
        # =====================================================

        if st.button(
            "Investigate Incident",
            width="stretch"
        ):

            st.session_state.selected_incident_id = (
                selected_incident
            )

            st.switch_page(
                "pages/6_incident_details.py"
            )
        if st.button(
            "Update Incident",
            type="primary",
            width="stretch"
        ):

            update_incident_status(
                selected_incident,
                new_status
            )

            assign_incident(
                selected_incident,
                analyst
            )

            st.success(
                f"{selected_incident} "
                f"updated successfully."
            )

            st.rerun()


else:

    st.success(
        "No incidents have been generated."
    )