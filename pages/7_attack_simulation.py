# pages/7_attack_simulation.py

import streamlit as st

from utils.styles import load_styles
from utils.network_simulations import (
    simulate_normal_traffic,
    simulate_port_scan,
    simulate_vpn_brute_force,
    simulate_beaconing,
    simulate_device_outage,
    restore_all_devices,
)
from utils.simulations import (
    simulate_brute_force,
    simulate_password_spray,
    simulate_impossible_travel,
    simulate_compromised_account,
)


load_styles()


st.title("Attack Simulation")

st.caption(
    "Generate controlled authentication attack patterns "
    "to validate AEGIS detections and incident workflows."
)


st.warning(
    "Simulation mode is active. Generated events are written "
    "to the AEGIS security event database."
)


st.divider()

st.header("Identity Attacks")
st.caption("Authentication attacks against the web portal.")


col1, col2 = st.columns(2)


with col1:

    st.subheader("Brute Force")

    st.caption(
        "Repeated failed authentication attempts against "
        "a single account from the same source."
    )

    if st.button(
        "Simulate Brute Force",
        width="stretch",
    ):

        source_ip, username, country = (
            simulate_brute_force()
        )

        st.cache_data.clear()

        st.error(
            f"Brute-force activity generated against "
            f"`{username}` from `{source_ip}` ({country})."
        )


with col2:

    st.subheader("Password Spray")

    st.caption(
        "A single source attempts authentication across "
        "multiple user accounts."
    )

    if st.button(
        "Simulate Password Spray",
        width="stretch",
    ):

        source_ip, sprayed_users, country = (
            simulate_password_spray()
        )

        st.cache_data.clear()

        st.warning(
            f"Password spray generated from `{source_ip}` "
            f"({country}) against "
            f"{len(sprayed_users)} accounts."
        )


st.divider()


col3, col4 = st.columns(2)


with col3:

    st.subheader("Impossible Travel")

    st.caption(
        "Successful logins for one account from "
        "geographically distant locations."
    )

    if st.button(
        "Simulate Impossible Travel",
        width="stretch",
    ):

        (
            username,
            source_ip_1,
            country_1,
            source_ip_2,
            country_2,
        ) = simulate_impossible_travel()

        st.cache_data.clear()

        st.warning(
            f"Impossible-travel scenario generated for "
            f"`{username}`: {country_1} → {country_2}."
        )


with col4:

    st.subheader("Compromised Account")

    st.caption(
        "Multiple failures followed by a successful "
        "authentication from the same source."
    )

    if st.button(
        "Simulate Compromised Account",
        width="stretch",
    ):

        source_ip, username, country = (
            simulate_compromised_account()
        )

        st.cache_data.clear()

        st.error(
            f"Potential account takeover generated for "
            f"`{username}` from `{source_ip}` ({country})."
        )


# =========================================================
# NETWORK SIMULATIONS
# =========================================================

st.divider()

st.header("Network Attacks")
st.caption(
    "Firewall, VPN, and flow telemetry for the Network Operations page."
)

net1, net2 = st.columns(2)

with net1:

    st.subheader("Port Scan")

    st.caption(
        "An external source probes 25 common ports on an "
        "internal server through the edge firewall."
    )

    if st.button("Simulate Port Scan", width="stretch"):
        src, target, role, ports = simulate_port_scan()
        st.cache_data.clear()
        st.error(
            f"Port scan generated: `{src}` probed {ports} ports on "
            f"`{target}` ({role})."
        )

with net2:

    st.subheader("VPN Brute Force")

    st.caption(
        "Repeated failed VPN logins for one account. Optionally "
        "followed by a successful session."
    )

    vpn_success = st.checkbox("Attacker gets in (successful session)")

    if st.button("Simulate VPN Brute Force", width="stretch"):
        src, user, country, attempts = simulate_vpn_brute_force(
            succeed=vpn_success
        )
        st.cache_data.clear()
        st.error(
            f"VPN brute force generated: {attempts} failures for `{user}` "
            f"from `{src}` ({country})"
            + (" — session established." if vpn_success else ".")
        )

st.divider()

net3, net4 = st.columns(2)

with net3:

    st.subheader("C2 Beaconing")

    st.caption(
        "An internal host checks in with an external server "
        "at regular intervals, like malware calling home."
    )

    if st.button("Simulate Beaconing", width="stretch"):
        src, dst, port, interval = simulate_beaconing()
        st.cache_data.clear()
        st.error(
            f"Beaconing generated: `{src}` → `{dst}:{port}` every ~{interval}s."
        )

with net4:

    st.subheader("Normal Traffic")

    st.caption(
        "Background web, DNS, and VPN activity so detections "
        "have to stand out from real-looking noise."
    )

    if st.button("Generate Normal Traffic", width="stretch"):
        count = simulate_normal_traffic()
        st.cache_data.clear()
        st.success(f"{count} legitimate network events generated.")

st.divider()

st.subheader("Infrastructure")

out1, out2 = st.columns(2)

with out1:
    if st.button("Simulate Switch Outage", width="stretch"):
        device = simulate_device_outage()
        st.cache_data.clear()
        if device:
            st.error(f"`{device}` is now down.")
        else:
            st.info("All access switches are already down.")

with out2:
    if st.button("Restore All Devices", width="stretch"):
        restore_all_devices()
        st.cache_data.clear()
        st.success("All network devices restored.")
