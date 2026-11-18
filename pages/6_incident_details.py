import streamlit as st
import pandas as pd

from utils.styles import load_styles
from utils.data_loader import load_events_between, load_network_events_between
from utils.incidents import (
    get_incidents,
    update_incident_status,
    assign_incident,
    add_incident_note,
    get_incident_notes,
)
from utils.mitre import get_mitre_context


load_styles()

st.title("Incident Details")
st.caption("Investigate evidence, ATT&CK context, and analyst response for a persistent SOC incident.")

incidents = get_incidents()

if incidents.empty:
    st.success("No incidents are available for investigation.")
    st.stop()

incident_ids = incidents["incident_id"].dropna().tolist()

requested_incident = st.session_state.get("selected_incident_id")

if requested_incident in incident_ids:
    default_index = incident_ids.index(requested_incident)
else:
    default_index = 0

selected_incident = st.selectbox(
    "Select Incident",
    incident_ids,
    index=default_index,
)

st.session_state.selected_incident_id = selected_incident

incident = incidents[incidents["incident_id"] == selected_incident].iloc[0]

source_ip = incident["source_ip"]
username = incident["username"]
incident_type = incident["incident_type"]
mitre_value = incident["mitre_technique"]
mitre = get_mitre_context(mitre_value=mitre_value, incident_type=incident_type)

# =========================================================
# INCIDENT EVIDENCE CORRELATION
# =========================================================

NETWORK_INCIDENT_TYPES = {"Port Scan", "VPN Brute Force", "C2 Beaconing"}
is_network_incident = incident_type in NETWORK_INCIDENT_TYPES

incident_created = pd.to_datetime(incident["created_at"])

# Search 15 minutes before the incident was created and 5 minutes
# after it. Events are loaded for that window directly, so older
# incidents still show their evidence.
evidence_start = incident_created - pd.Timedelta(minutes=15)
evidence_end = incident_created + pd.Timedelta(minutes=5)

if is_network_incident:
    df = load_network_events_between(evidence_start.to_pydatetime(), evidence_end.to_pydatetime())
else:
    df = load_events_between(evidence_start.to_pydatetime(), evidence_end.to_pydatetime())

if df.empty:
    related_events = pd.DataFrame()

else:
    time_match = (
        (df["event_time"] >= evidence_start)
        &
        (df["event_time"] <= evidence_end)
    )

    source_match = (
        df["source_ip"].astype(str)
        == str(source_ip)
    )

    # -----------------------------------------------------
    # NETWORK INCIDENTS
    # Port scans and beaconing correlate by source IP;
    # VPN brute force also matches the targeted account.
    # -----------------------------------------------------

    if is_network_incident:

        if incident_type == "VPN Brute Force" and pd.notna(username):
            related_events = df[
                time_match
                & source_match
                & (df["username"].fillna("").astype(str) == str(username))
            ].copy()
        else:
            related_events = df[
                time_match
                & source_match
            ].copy()

    # -----------------------------------------------------
    # PASSWORD SPRAY
    # Correlate by source IP because one attacker
    # targets multiple usernames.
    # -----------------------------------------------------

    elif incident_type == "Password Spray":

        related_events = df[
            time_match
            & source_match
        ].copy()

    # -----------------------------------------------------
    # BRUTE FORCE
    # Same source IP targeting the same username.
    # -----------------------------------------------------

    elif incident_type == "Brute Force Attempt":

        user_match = (
            df["username"]
            .fillna("")
            .astype(str)
            == str(username)
        )

        related_events = df[
            time_match
            & source_match
            & user_match
        ].copy()

    # -----------------------------------------------------
    # ACCOUNT TAKEOVER
    # Follow activity involving the affected account.
    # -----------------------------------------------------

    elif incident_type == "Potential Account Takeover":

        user_match = (
            df["username"]
            .fillna("")
            .astype(str)
            == str(username)
        )

        related_events = df[
            time_match
            & user_match
        ].copy()

    # -----------------------------------------------------
    # IMPOSSIBLE TRAVEL
    # Follow the affected user's authentication activity.
    # -----------------------------------------------------

    elif incident_type == "Impossible Travel":

        user_match = (
            df["username"]
            .fillna("")
            .astype(str)
            == str(username)
        )

        related_events = df[
            time_match
            & user_match
        ].copy()

    # -----------------------------------------------------
    # FALLBACK
    # Unknown/future detection types.
    # -----------------------------------------------------

    else:

        if pd.notna(username) and str(username).strip():

            user_match = (
                df["username"]
                .fillna("")
                .astype(str)
                == str(username)
            )

            related_events = df[
                time_match
                & (source_match | user_match)
            ].copy()

        else:

            related_events = df[
                time_match
                & source_match
            ].copy()

    related_events = related_events.sort_values(
        "event_time",
        ascending=False,
    )
failed_events = 0
successful_events = 0
unique_users = 0
unique_countries = 0

if not related_events.empty:
    failed_events = int((related_events["status"] == "failed").sum())
    successful_events = int((related_events["status"] == "success").sum())
    unique_users = int(related_events["username"].nunique())
    unique_countries = int(related_events["geo_country"].nunique())

# =========================================================
# INCIDENT HEADER
# =========================================================

st.subheader(selected_incident)

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Severity", incident["severity"])
m2.metric("Status", incident["status"])
m3.metric("Failed Attempts", int(incident["failed_attempts"] or 0))
m4.metric("Related Events", len(related_events))
m5.metric("Assigned To", incident["assigned_to"] or "Unassigned")

st.divider()

# =========================================================
# INCIDENT / MITRE CONTEXT
# =========================================================

left, right = st.columns([1, 1])

with left:
    st.subheader("Incident Context")
    st.write(f"**Incident Type:** {incident_type}")
    st.write(f"**Source IP:** `{source_ip}`")
    st.write(
        f"**Username:** `{username if pd.notna(username) and username else 'Multiple / Unknown'}`"
    )
    st.write(f"**Created At:** {incident['created_at']}")
    st.write(f"**Updated At:** {incident['updated_at']}")

with right:
    st.subheader("MITRE ATT&CK")
    st.write(f"**Technique:** `{mitre['technique_id']}` — {mitre['name']}")
    st.write(f"**Tactic:** {mitre['tactic']}")
    st.caption(mitre["description"])

# =========================================================
# EVIDENCE SUMMARY
# =========================================================

st.divider()
st.subheader("Evidence Summary")

e1, e2, e3, e4 = st.columns(4)
e1.metric("Failed Events", failed_events)
e2.metric("Successful Events", successful_events)
e3.metric("Users Observed", unique_users)
e4.metric("Countries Observed", unique_countries)

if not related_events.empty:
    first_seen = related_events["event_time"].min()
    last_seen = related_events["event_time"].max()
    st.caption(
        f"Related activity observed from {first_seen.strftime('%m/%d/%Y %I:%M %p')} "
        f"through {last_seen.strftime('%m/%d/%Y %I:%M %p')}"
    )
else:
    st.info("No related telemetry was found within 15 minutes of this incident.")

# =========================================================
# RESPONSE GUIDANCE
# =========================================================

st.divider()
st.subheader("Recommended Response Actions")

for action in mitre["recommended_actions"]:
    st.markdown(f"- {action}")

# =========================================================
# INCIDENT TIMELINE
# =========================================================

st.divider()
st.subheader("Incident Timeline")
st.caption(
    "Chronological reconstruction of authentication and network "
    "activity correlated with this incident."
)

if related_events.empty:
    st.info("No timeline events are available for this incident.")

else:
    timeline_events = related_events.sort_values(
        "event_time",
        ascending=True,
    ).copy()

    failures_seen = 0

    for _, event in timeline_events.iterrows():

        event_time = pd.to_datetime(event["event_time"])

        status = str(
            event.get("status", "unknown")
        ).lower()

        event_username = event.get(
            "username",
            "Unknown",
        )

        event_ip = event.get(
            "source_ip",
            "Unknown",
        )

        country = event.get(
            "geo_country",
            "Unknown",
        )

        event_type = event.get(
            "event_type",
            "Authentication",
        )

        device = event.get(
            "device_type",
            "Unknown",
        )

        # ---------------------------------------------
        # Determine event classification
        # ---------------------------------------------

        if status == "failed":

            failures_seen += 1

            icon = "❌"
            event_label = "AUTHENTICATION FAILED"

        elif status == "success":

            icon = "✅"
            event_label = "AUTHENTICATION SUCCESS"

        else:

            icon = "🔍"
            event_label = str(event_type).upper()

        # ---------------------------------------------
        # Render event
        # ---------------------------------------------

        st.markdown(
            f"""
### {icon} {event_label}

**{event_time.strftime('%m/%d/%Y %I:%M:%S %p')}**

**User:** `{event_username}`  
**Source IP:** `{event_ip}`  
**Country:** {country}  
**Device:** {device}
"""
        )

        # ---------------------------------------------
        # Highlight suspicious success after failures
        # ---------------------------------------------

        if status == "success" and failures_seen > 0:

            st.warning(
                f"Successful authentication occurred after "
                f"{failures_seen} failed authentication attempt(s) "
                f"from correlated activity."
            )

            st.markdown("↓")

    # =====================================================
    # AEGIS DETECTION EVENT
    # =====================================================

    incident_time = pd.to_datetime(
        incident["created_at"]
    )

    st.markdown(
        f"""
### 🚨 AEGIS INCIDENT GENERATED

**{incident_time.strftime('%m/%d/%Y %I:%M:%S %p')}**

**Incident:** `{selected_incident}`  
**Detection:** {incident_type}  
**Severity:** {incident["severity"]}  
**MITRE ATT&CK:** `{mitre['technique_id']}` — {mitre['name']}
"""
    )

# =========================================================
# ANALYST WORKFLOW
# =========================================================

st.divider()
st.subheader("Analyst Workflow")

# =========================================================
# INVESTIGATION JOURNAL
# =========================================================

st.divider()
st.subheader("Investigation Journal")

incident_notes = get_incident_notes(selected_incident)

if incident_notes.empty:
    st.info("No investigation notes have been recorded for this incident.")
else:
    for _, note_row in incident_notes.iterrows():

        note_time = pd.to_datetime(
            note_row["created_at"]
        ).strftime("%m/%d/%Y %I:%M %p")

        st.markdown(
            f"**{note_row['analyst']}**  \n"
            f"*{note_time}*"
        )

        st.write(note_row["note"])
        st.divider()


# =========================================================
# ADD INVESTIGATION NOTE
# =========================================================

note_key = f"new_note_{selected_incident}"
clear_key = f"clear_note_input_{selected_incident}"

# Clear the text area BEFORE Streamlit creates the widget.
# This runs on the rerun after a note is successfully saved.
if st.session_state.get(clear_key, False):
    st.session_state[note_key] = ""
    st.session_state[clear_key] = False


note_text = st.text_area(
    "Add Investigation Note",
    placeholder=(
        "Document findings, evidence reviewed, "
        "actions taken, and next steps..."
    ),
    key=note_key,
)


if st.button(
    "Save Investigation Note",
    type="primary",
    width="stretch",
):
    clean_note = note_text.strip()

    if not clean_note:
        st.warning(
            "Enter an investigation note before saving."
        )

    else:
        analyst_name = incident["assigned_to"]

        if (
            pd.isna(analyst_name)
            or not str(analyst_name).strip()
            or analyst_name == "Unassigned"
        ):
            analyst_name = (
                st.session_state.get("analyst_name")
                or "SOC Analyst"
            )

        add_incident_note(
            selected_incident,
            analyst_name,
            clean_note,
        )

        # Mark this specific incident's note box
        # to be cleared on the next rerun.
        st.session_state[clear_key] = True

        st.rerun()

status_options = ["Open", "Investigating", "Contained", "Closed"]
current_status = incident["status"] if incident["status"] in status_options else "Open"

workflow_col1, workflow_col2 = st.columns(2)

with workflow_col1:
    new_status = st.selectbox(
        "Incident Status",
        status_options,
        index=status_options.index(current_status),
    )

with workflow_col2:
    current_analyst = incident["assigned_to"]
    if pd.isna(current_analyst) or not str(current_analyst).strip():
        current_analyst = "Unassigned"

    analyst = st.text_input("Assigned Analyst", value=str(current_analyst))

button_col1, button_col2, button_col3 = st.columns(3)

with button_col1:
    if st.button("Assign to Me", width="stretch"):
        analyst_name = st.session_state.get("analyst_name") or "SOC Analyst"
        assign_incident(selected_incident, analyst_name)
        update_incident_status(selected_incident, "Investigating")
        st.rerun()

with button_col2:
    if st.button("Save Status / Assignment", type="primary", width="stretch"):
        update_incident_status(selected_incident, new_status)
        assign_incident(selected_incident, analyst)
        st.success(f"{selected_incident} updated successfully.")
        st.rerun()

with button_col3:
    if st.button("Resolve Incident", width="stretch"):
        update_incident_status(selected_incident, "Closed")
        st.success(f"{selected_incident} marked Closed.")
        st.rerun()
