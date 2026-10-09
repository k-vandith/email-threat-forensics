"""Email forensics workstation."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import pandas as pd
import streamlit as st
from src.email_analyzer import analyze_eml_file, parse_email
from src.email_features import export_html_report, trace_hops
from src.ui_theme import theme_css

def main() -> None:
    st.set_page_config(page_title="Email forensics", layout="wide")
    st.markdown(theme_css("#c4a15a"), unsafe_allow_html=True)
    st.markdown('<div class="top"><div><div class="kicker">Digital investigation</div><p class="title">Email threat forensics</p></div><div class="pill">Headers · hops · IOCs</div></div>', unsafe_allow_html=True)
    sample = ROOT / "data" / "sample" / "phishing_sample.eml"
    upload = st.sidebar.file_uploader("EML", type=["eml", "txt"])
    raw = ""
    name = "sample"
    if upload is not None:
        raw = upload.getvalue().decode("utf-8", errors="replace")
        name = Path(upload.name).name
        analysis = parse_email(raw)
    elif sample.exists():
        raw = sample.read_text(encoding="utf-8", errors="replace")
        analysis = analyze_eml_file(sample)
        name = sample.name
    else:
        st.markdown('<div class="panel"><p class="muted">No message loaded. Generate demo data or upload an .eml file.</p></div>', unsafe_allow_html=True)
        return
    hops = trace_hops(raw)
    st.markdown(f'<div class="panel"><div class="kicker">{name}</div><p class="title">Threat score {analysis.threat_score:.2f}</p><p class="muted">{analysis.subject or "(no subject)"} · {analysis.sender or "unknown sender"}</p></div>', unsafe_allow_html=True)
    left, right = st.columns([1.2, 1])
    with left:
        st.markdown("### Authentication")
        st.write(f"SPF {analysis.spf} · DKIM {analysis.dkim} · DMARC {analysis.dmarc}")
        if analysis.phishing_indicators:
            for item in analysis.phishing_indicators:
                st.warning(item)
        else:
            st.success("No phishing indicators flagged by the local rules.")
        st.markdown("### URLs and IOCs")
        st.dataframe(pd.DataFrame({"url": analysis.urls or ["—"]}), hide_index=True, width="stretch")
        if analysis.iocs:
            st.write(", ".join(analysis.iocs))
    with right:
        st.markdown("### Hops")
        if hops:
            st.dataframe(pd.DataFrame([{"order": h.order, "ip": h.ip, "geo": h.geo.get("city", ""), "country": h.geo.get("country", "")} for h in hops]), hide_index=True, width="stretch")
        st.markdown("### Timeline")
        for line in analysis.timeline or ["No Received timeline parsed."]:
            st.caption(line)
    st.download_button("HTML evidence report", export_html_report(analysis, hops), file_name="email_report.html")

if __name__ == "__main__":
    main()
