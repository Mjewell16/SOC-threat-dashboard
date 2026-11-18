import streamlit as st

from utils.styles import load_styles
from utils.auth import (
    initialize_auth_state,
    authenticate_user,
    login_user,
)


# =========================================================
# INITIALIZE
# =========================================================

load_styles()
initialize_auth_state()



# =========================================================
# LOGIN PAGE STYLING
# =========================================================

st.markdown(
    """
    <style>

    /* Hide sidebar while logged out */
    [data-testid="stSidebar"] {
        display: none;
    }

    /* Main page width */
    .block-container {
        max-width: 760px;
        padding-top: 4rem;
        padding-bottom: 1rem;
    }

    /* AEGIS branding */
    .aegis-logo {
        text-align: center;
        color: #00F5D4;
        font-size: 52px;
        font-weight: 800;
        letter-spacing: 10px;
        margin-bottom: 2px;
    }

    .aegis-subtitle {
        text-align: center;
        color: #94A3B8;
        font-size: 12px;
        letter-spacing: 3px;
        text-transform: uppercase;
        margin-bottom: 38px;
    }

    .login-heading {
        text-align: center;
        color: #E5E7EB;
        font-size: 22px;
        font-weight: 700;
        margin-bottom: 5px;
    }

    .login-description {
        text-align: center;
        color: #64748B;
        font-size: 14px;
        margin-bottom: 20px;
    }

    .demo-credentials {
        border: 1px solid rgba(0, 245, 212, 0.16);
        background: rgba(0, 245, 212, 0.035);
        border-radius: 10px;
        padding: 12px 16px;
        margin: 0 0 18px 0;
        color: #94A3B8;
        font-size: 12px;
        line-height: 1.65;
    }

    .demo-credentials strong {
        color: #D1FAE5;
    }

    /* Login form */
    div[data-testid="stForm"] {
        border: 1px solid rgba(0, 245, 212, 0.18);
        border-radius: 14px;
        padding: 24px;
        background: rgba(10, 15, 20, 0.75);
    }

    /* Inputs */
    .stTextInput input {
        background-color: #111827;
        color: #E5E7EB;
        border: 1px solid #263244;
        border-radius: 8px;
    }

    .stTextInput input:focus {
        border-color: #00F5D4;
        box-shadow: 0 0 0 1px #00F5D4;
    }

    /* Sign in */
    [data-testid="stFormSubmitButton"] button {
        width: 100%;
        height: 46px;
        background-color: #00C9A7;
        color: #07110F;
        border: none;
        border-radius: 8px;
        font-weight: 700;
    }

    [data-testid="stFormSubmitButton"] button:hover {
        background-color: #00F5D4;
        color: #07110F;
    }

    .security-notice {
        text-align: center;
        color: #64748B;
        font-size: 11px;
        margin-top: 24px;
        line-height: 1.5;
    }

    .system-status {
        text-align: center;
        color: #22C55E;
        font-size: 11px;
        margin-top: 7px;
        letter-spacing: 0.5px;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# BRANDING
# =========================================================

st.markdown(
    """
    <div class="aegis-logo">AEGIS</div>
    <div class="aegis-subtitle">Security Operations Platform</div>
    <div class="login-heading">Analyst Authentication</div>
    <div class="login-description">
        Sign in to access the AEGIS Security Operations Center.
    </div>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# DEMO CREDENTIALS
# =========================================================

st.markdown(
    """
    <div class="demo-credentials">
        <strong>Portfolio Demo Access</strong><br>
        Username: <strong>analyst</strong><br>
        Password: <strong>Aegis2026!</strong>
    </div>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# ANALYST AUTHENTICATION
# =========================================================

with st.form(
    "aegis_login_form",
    clear_on_submit=False,
):

    username = st.text_input(
        "Username",
        placeholder="Enter analyst username",
    )

    password = st.text_input(
        "Password",
        type="password",
        placeholder="Enter password",
    )

    submitted = st.form_submit_button(
        "Sign In",
        width="stretch",
    )

if submitted:

    user = authenticate_user(
        username,
        password,
    )

    if user:
        login_user(user)
        st.rerun()
    else:
        st.error(
            "Authentication failed. Use the portfolio demo "
            "credentials shown above."
        )


# =========================================================
# FOOTER
# =========================================================

st.markdown(
    """
    <div class="security-notice">
        Authorized personnel only. Authentication activity is monitored and recorded.
    </div>
    <div class="system-status">
        ● AEGIS SERVICES ONLINE
    </div>
    """,
    unsafe_allow_html=True,
)
