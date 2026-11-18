import streamlit as st

from utils.auth import (
    initialize_auth_state,
    logout_user,
)


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="AEGIS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =========================================================
# AUTHENTICATION STATE
# =========================================================

initialize_auth_state()


# =========================================================
# LOGGED OUT
# =========================================================

if not st.session_state.authenticated:

    login_page = st.Page(
        "pages/0_login.py",
        title="Login",
        icon=":material/login:",
        default=True,
    )

    navigation = st.navigation(
        [login_page]
    )

    navigation.run()


# =========================================================
# LOGGED IN
# =========================================================

else:

    command_center = st.Page(
        "pages/0_command_center.py",
        title="Command Center",
        icon=":material/dashboard:",
        default=True,
    )

    incident_queue = st.Page(
        "pages/2_incident_queue.py",
        title="Incident Queue",
        icon=":material/warning:",
    )

    threat_intelligence = st.Page(
        "pages/3_threat_intelligence.py",
        title="Threat Intelligence",
        icon=":material/travel_explore:",
    )

    user_investigation = st.Page(
        "pages/4_user_investigation.py",
        title="User Investigation",
        icon=":material/person_search:",
    )

    detection_rules = st.Page(
        "pages/5_detection_rules.py",
        title="Detection Rules",
        icon=":material/rule:",
    )

    incident_details = st.Page(
        "pages/6_incident_details.py",
        title="Incident Details",
        icon=":material/manage_search:",
    )

    network_operations = st.Page(
        "pages/8_network_operations.py",
        title="Network Operations",
        icon=":material/lan:",
    )

    attack_simulation = st.Page(
        "pages/7_attack_simulation.py",
        title="Attack Simulation",
        icon=":material/bug_report:",
    )


    # =====================================================
    # TOP NAVIGATION
    # =====================================================

    navigation = st.navigation(
        [
            command_center,
            incident_queue,
            network_operations,
            threat_intelligence,
            user_investigation,
            detection_rules,
            incident_details,
            attack_simulation,
        ],
        position="top",
    )

    # =====================================================
    # SIDEBAR ANALYST SESSION
    # =====================================================

    with st.sidebar:

        st.caption("AUTHENTICATED ANALYST")

        st.markdown(
            f"**{st.session_state.analyst_name}**"
        )

        st.caption(
            st.session_state.role
        )

        st.divider()

        if st.button(
            "Logout",
            icon=":material/logout:",
            width="stretch",
        ):

            logout_user()
            st.rerun()


    navigation.run()