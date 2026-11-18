import os
import warnings

import mysql.connector
import streamlit as st


# pandas prefers SQLAlchemy connections but works fine with
# mysql-connector; hide its repeated "not tested" warning.
warnings.filterwarnings(
    "ignore",
    message="pandas only supports SQLAlchemy",
    category=UserWarning,
)


def _get_setting(key, default=None):
    """
    Read a database setting from an environment variable first,
    then from Streamlit secrets (.streamlit/secrets.toml).
    Credentials are never stored in source code.
    """
    env_value = os.environ.get(f"AEGIS_DB_{key.upper()}")
    if env_value:
        return env_value

    try:
        return st.secrets["database"][key]
    except (KeyError, FileNotFoundError):
        return default


def get_connection():
    password = _get_setting("password")

    if not password:
        raise RuntimeError(
            "Database password not configured. Copy "
            ".streamlit/secrets.toml.example to .streamlit/secrets.toml "
            "and fill in your MySQL credentials, or set AEGIS_DB_PASSWORD."
        )

    return mysql.connector.connect(
        host=_get_setting("host", "127.0.0.1"),
        port=int(_get_setting("port", 3306)),
        user=_get_setting("user", "aegis_app"),
        password=password,
        database=_get_setting("name", "soc_dashboard"),
    )
