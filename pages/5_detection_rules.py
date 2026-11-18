import streamlit as st
import pandas as pd

from utils.styles import load_styles
from utils.mitre import get_mitre_context
from utils.detection_rules import DETECTION_RULES, mitre_label


load_styles()

st.title("Detection Rules")
st.caption("Detection engineering logic and MITRE ATT&CK coverage for AEGIS authentication analytics.")

rules = pd.DataFrame([
    {
        "Rule ID": rule["rule_id"],
        "Category": rule.get("category", "Identity"),
        "Rule Name": rule["name"],
        "Condition": rule["condition"],
        "Severity": rule["severity"],
        "MITRE": mitre_label(key),
        "Tactic": rule["tactic"],
    }
    for key, rule in DETECTION_RULES.items()
])

st.dataframe(rules, width="stretch", hide_index=True)

st.divider()
st.subheader("ATT&CK Coverage")

for mitre_value in sorted({mitre_label(key) for key in DETECTION_RULES}):
    context = get_mitre_context(mitre_value=mitre_value)

    with st.expander(f"{context['technique_id']} — {context['name']}"):
        st.write(f"**Tactic:** {context['tactic']}")
        st.write(context["description"])
        st.write("**AEGIS response guidance:**")
        for action in context["recommended_actions"]:
            st.markdown(f"- {action}")
