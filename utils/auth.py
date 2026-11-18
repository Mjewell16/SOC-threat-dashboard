import hashlib
import hmac
import streamlit as st


# =========================================================
# DEMO USERS
# =========================================================

DEMO_USERS = {

    "analyst": {
        "name": "Mason Jewell",
        "role": "SOC Analyst",
        "password_hash": hashlib.sha256(
            "Aegis2026!".encode()
        ).hexdigest(),
    },

    "admin": {
        "name": "AEGIS Administrator",
        "role": "SOC Administrator",
        "password_hash": hashlib.sha256(
            "Admin2026!".encode()
        ).hexdigest(),
    },
}


# =========================================================
# PASSWORD HASHING
# =========================================================

def hash_password(password):

    return hashlib.sha256(
        password.encode()
    ).hexdigest()


# =========================================================
# AUTHENTICATE USER
# =========================================================

def authenticate_user(
    username,
    password,
):

    username = username.strip().lower()

    user = DEMO_USERS.get(username)

    if not user:
        return None

    supplied_hash = hash_password(password)

    if hmac.compare_digest(
        supplied_hash,
        user["password_hash"],
    ):

        return {
            "username": username,
            "name": user["name"],
            "role": user["role"],
        }

    return None


# =========================================================
# SESSION STATE
# =========================================================

def initialize_auth_state():

    defaults = {
        "authenticated": False,
        "username": None,
        "analyst_name": None,
        "role": None,
    }

    for key, value in defaults.items():

        if key not in st.session_state:
            st.session_state[key] = value


# =========================================================
# LOGIN
# =========================================================

def login_user(user):

    st.session_state.authenticated = True

    st.session_state.username = (
        user["username"]
    )

    st.session_state.analyst_name = (
        user["name"]
    )

    st.session_state.role = (
        user["role"]
    )


# =========================================================
# LOGOUT
# =========================================================

def logout_user():

    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.analyst_name = None
    st.session_state.role = None