import streamlit as st


def load_styles():
    st.markdown("""
<style>

/* =========================================================
   MAIN APP
   ========================================================= */

.stApp {
    background-color: #0A0F14;
    color: #E5E7EB;
}

/* MAIN CONTAINER */
.block-container {
    padding-top: 1.6rem;
    padding-bottom: 2rem;
    max-width: 94%;
}


/* =========================================================
   TOP NAVIGATION
   ========================================================= */

/* HEADER / NAV AREA */
header[data-testid="stHeader"] {
    background:
        linear-gradient(
            180deg,
            rgba(10,15,20,0.98),
            rgba(10,15,20,0.94)
        );

    border-bottom: 1px solid rgba(0,245,212,0.12);

    box-shadow:
        0 5px 20px rgba(0,0,0,0.20);
}

/* TOP NAVIGATION CONTAINER */
[data-testid="stNavigation"] {
    background: transparent;
}

/* NAVIGATION LINKS */
[data-testid="stNavigation"] a {
    color: #AEB8C4;

    font-weight: 600;
    font-size: 14px;

    border-radius: 8px;

    padding:
        7px
        11px;

    margin:
        0
        3px;

    border:
        1px solid
        transparent;

    transition:
        all 0.2s ease;
}

/* NAVIGATION HOVER */
[data-testid="stNavigation"] a:hover {
    color: #E5FFFA;

    background:
        rgba(0,245,212,0.06);

    border:
        1px solid
        rgba(0,245,212,0.14);

    transform:
        translateY(-1px);
}

/* ACTIVE NAVIGATION ITEM */
[data-testid="stNavigation"] a[aria-current="page"] {
    color: #00F5D4;

    background:
        linear-gradient(
            145deg,
            rgba(0,245,212,0.16),
            rgba(0,245,212,0.05)
        );

    border:
        1px solid
        rgba(0,245,212,0.30);

    box-shadow:
        0 0 14px rgba(0,245,212,0.07);

    font-weight: 700;
}

/* REMOVE DEFAULT SIDEBAR IF EMPTY */
section[data-testid="stSidebar"] {
    display: none;
}


/* =========================================================
   HEADERS
   ========================================================= */

h1 {
    color: #00F5D4;

    font-weight: 800;

    letter-spacing: 1px;

    text-transform: uppercase;
}

h2,
h3 {
    color: #D1D5DB;

    text-transform: uppercase;

    letter-spacing: 0.5px;
}


/* =========================================================
   METRIC CARDS
   ========================================================= */

[data-testid="stMetric"] {
    background:
        linear-gradient(
            145deg,
            rgba(16,24,32,0.95),
            rgba(20,30,40,0.95)
        );

    border:
        1px solid
        rgba(0,255,200,0.18);

    padding: 18px;

    border-radius: 16px;

    box-shadow:
        0 0 10px rgba(0,255,200,0.05),
        0 6px 18px rgba(0,0,0,0.45);

    transition:
        all 0.25s ease;
}

/* METRIC HOVER */
[data-testid="stMetric"]:hover {
    transform:
        translateY(-4px);

    border:
        1px solid
        rgba(0,255,200,0.4);

    box-shadow:
        0 0 16px rgba(0,255,200,0.12),
        0 10px 24px rgba(0,0,0,0.55);
}

/* METRIC VALUES */
[data-testid="stMetricValue"] {
    color: #00F5D4;

    font-size: 30px;

    font-weight: 700;
}


/* =========================================================
   ALERT BOXES
   ========================================================= */

[data-testid="stAlert"] {
    border-radius: 12px;

    border:
        1px solid
        rgba(255,255,255,0.08);

    box-shadow:
        0 4px 14px rgba(0,0,0,0.4);
}


/* =========================================================
   DATA TABLES
   ========================================================= */

[data-testid="stDataFrame"] {
    background-color:
        rgba(15,23,32,0.96);

    border-radius: 14px;

    padding: 10px;

    border:
        1px solid
        rgba(0,255,200,0.08);

    box-shadow:
        0 6px 18px rgba(0,0,0,0.4);
}


/* =========================================================
   CHARTS
   ========================================================= */

.element-container:has(canvas) {
    background-color:
        rgba(15,23,32,0.95);

    border-radius: 16px;

    padding: 16px;

    border:
        1px solid
        rgba(0,255,200,0.08);

    box-shadow:
        0 8px 20px rgba(0,0,0,0.45);

    transition:
        all 0.25s ease;
}

.element-container:has(canvas):hover {
    transform:
        translateY(-3px);

    box-shadow:
        0 0 14px rgba(0,255,200,0.08),
        0 10px 22px rgba(0,0,0,0.55);
}


/* =========================================================
   MAP
   ========================================================= */

[data-testid="stDeckGlJsonChart"] {
    border-radius: 12px;

    overflow: hidden;

    border:
        1px solid
        rgba(0,255,200,0.12);

    box-shadow:
        0 8px 20px rgba(0,0,0,0.45);
}


/* =========================================================
   FORMS / INPUTS
   ========================================================= */

/* TEXT INPUTS */
[data-testid="stTextInput"] input {
    background-color:
        rgba(25,30,40,0.95);

    border:
        1px solid
        rgba(255,255,255,0.08);

    border-radius: 8px;

    color: #E5E7EB;
}

/* TEXT INPUT FOCUS */
[data-testid="stTextInput"] input:focus {
    border-color:
        rgba(0,245,212,0.45);

    box-shadow:
        0 0 0 1px
        rgba(0,245,212,0.18);
}

/* SELECT BOXES */
[data-baseweb="select"] > div {
    background-color:
        rgba(25,30,40,0.95);

    border-color:
        rgba(255,255,255,0.08);
}

/* FORM CONTAINER */
[data-testid="stForm"] {
    border:
        1px solid
        rgba(0,245,212,0.12);

    border-radius: 12px;

    background-color:
        rgba(10,15,20,0.35);

    padding: 14px;
}


/* =========================================================
   BUTTONS
   ========================================================= */

.stButton > button,
.stFormSubmitButton > button {
    border-radius: 8px;

    border:
        1px solid
        rgba(0,245,212,0.20);

    background:
        linear-gradient(
            145deg,
            rgba(20,28,38,0.95),
            rgba(14,20,28,0.95)
        );

    color: #E5E7EB;

    font-weight: 600;

    transition:
        all 0.2s ease;
}

/* BUTTON HOVER */
.stButton > button:hover,
.stFormSubmitButton > button:hover {
    border-color:
        rgba(0,245,212,0.50);

    color: #00F5D4;

    box-shadow:
        0 0 12px
        rgba(0,245,212,0.10);

    transform:
        translateY(-1px);
}


/* =========================================================
   DIVIDERS
   ========================================================= */

hr {
    border: none;

    border-top:
        1px solid
        rgba(0,255,200,0.10);

    margin-top: 1.3rem;

    margin-bottom: 1.3rem;
}


/* =========================================================
   SCROLLBAR
   ========================================================= */

::-webkit-scrollbar {
    width: 10px;
}

::-webkit-scrollbar-track {
    background: #0F172A;
}

::-webkit-scrollbar-thumb {
    background:
        rgba(0,255,200,0.30);

    border-radius: 10px;
}

::-webkit-scrollbar-thumb:hover {
    background:
        rgba(0,255,200,0.50);
}

</style>
""", unsafe_allow_html=True)