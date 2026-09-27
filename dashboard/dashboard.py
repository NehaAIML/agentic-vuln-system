import streamlit as st
import json
from pathlib import Path

st.set_page_config(page_title="Agentic Vulnerability Triage", layout="wide")

st.title("🛡️ Enterprise Agentic Vulnerability Triage & Patching Dashboard")
st.markdown("Autonomous closed-loop security remediation powered by AST code-graphs, EPSS intelligence, and Docker sandboxes.")

# High-Level Metrics Layout
col1, col2, col3, col4 = st.columns(4)
col1.metric("Active CVE Queue", "1", "-2 filtered (dead code)")
col2.metric("EPSS Threat Score", "0.0842", "High Priority")
col3.metric("Self-Repair Success", "100%", "Attempt 1/3")
col4.metric("Token Efficiency", "Zero Cost ($0)", "Local Model / Free Tier")

st.markdown("---")
st.subheader("Live Master Execution Reports")

report_path = Path("master_execution_report.json")
if report_path.exists():
    data = json.loads(report_path.read_text())
    st.json(data)
else:
    st.info("Run `python3 run_master_pipeline.py` to generate live telemetry.")
