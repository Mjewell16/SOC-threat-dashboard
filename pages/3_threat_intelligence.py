import streamlit as st

from utils.styles import load_styles
from utils.data_loader import load_data


load_styles()

st.title("Threat Intelligence")
st.caption("Search source IPs and review observed activity.")

df = load_data()

ip_address = st.text_input(
    "Search Source IP",
    placeholder="Example: 185.220.101.12"
)

if ip_address:
    results = df[
        df["source_ip"] == ip_address.strip()
    ]

    if not results.empty:

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total Events",
            len(results)
        )

        col2.metric(
            "Countries Observed",
            results["geo_country"].nunique()
        )

        col3.metric(
            "Users Targeted",
            results["username"].nunique()
        )

        st.divider()

        st.subheader("Related Events")

        related_events = results.sort_values(
            "event_time",
            ascending=False
        )

        st.dataframe(
            related_events,
            width="stretch",
            hide_index=True
        )

    else:
        st.warning(
            f"No observed activity found for `{ip_address}`."
        )