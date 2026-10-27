import streamlit as st
import requests

st.set_page_config(page_title="VOID Code Reviewer", page_icon="🛡️", layout="wide")

st.title("🛡️ VOID: Autonomous Security Audit & Verification Engine")
st.caption("Deterministic SAST + PyPI Validation + LangGraph Self-Correction Sandbox")

# Sidebar configurations
backend_url = st.sidebar.text_input("Backend API Endpoint", value="http://localhost:8000/api/v1/audit")

sample_vulnerable_code = """import os
import sqlite3

def authenticate(user_token):
    # Untrusted deserialization / injection hazard
    conn = sqlite3.connect("app.db")
    query = f"SELECT * FROM accounts WHERE token = '{user_token}'"
    return conn.execute(query).fetchall()
"""

col_left, col_right = st.columns(2)

with col_left:
    st.subheader("Source Code Input")
    source_code = st.text_area("Python Code", value=sample_vulnerable_code, height=360)
    audit_button = st.button("Audit & Auto-Repair Code", type="primary", use_container_width=True)

if audit_button:
    with st.spinner("Analyzing AST, screening SAST, and executing sandbox repair..."):
        try:
            res = requests.post(
                backend_url,
                json={"code": source_code, "language": "python"},
                timeout=90
            )
            if res.status_code == 200:
                result = res.json()
                with col_right:
                    st.subheader("Repair Telemetry")
                    m1, m2 = st.columns(2)
                    m1.metric("Sandbox Tests", result.get("test_status", "UNKNOWN"))
                    m2.metric("Correction Attempts", result.get("retries", 0))

                    st.subheader("Audit Findings")
                    for note in result.get("audit_notes", []):
                        st.warning(note.get("issue"))

                st.divider()
                st.subheader("Unified Git Diff")
                st.code(result.get("diff", "No modifications generated."), language="diff")

                st.subheader("Candidate Patched Code")
                st.code(result.get("refactored_code", ""), language="python")
            else:
                st.error(f"API Error ({res.status_code}): {res.text}")
        except requests.exceptions.RequestException as err:
            st.error(f"Could not connect to backend at {backend_url}: {err}")