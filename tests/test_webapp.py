from pathlib import Path
import pytest

from src.email_features import export_html_report, trace_hops
from src.email_analyzer import parse_email
from src.webapp import MAX_MESSAGE_BYTES, analyze_message

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "sample" / "phishing_sample.eml"


def test_sample_analysis_exposes_casework_fields():
    result = analyze_message(SAMPLE.read_text(encoding="utf-8"), "../../case.eml")
    assert result["filename"] == "case.eml"
    assert result["risk_band"] == "critical"
    assert result["spf"] == result["dkim"] == result["dmarc"] == "fail"
    assert result["threat_score"] >= 0.8
    assert result["hops"]
    assert any(value.startswith("http://") for value in result["urls"])
    assert "network_lookups" not in result


def test_rejects_empty_and_oversized_messages():
    with pytest.raises(ValueError, match="empty"):
        analyze_message("")
    with pytest.raises(ValueError, match="2 MB"):
        analyze_message("x" * (MAX_MESSAGE_BYTES + 1))


def test_unknown_authentication_does_not_become_a_pass():
    result = analyze_message("From: sender@example.test\nSubject: hello\n\nHi")
    assert result["spf"] == result["dkim"] == result["dmarc"] == "unknown"
    assert result["threat_score"] == 0


def test_html_evidence_report_escapes_untrusted_message_values():
    raw = "From: analyst@example.test\nSubject: <script>alert(1)</script>\nReceived: from bad (<img src=x>)\n\nhello"
    report = export_html_report(parse_email(raw), trace_hops(raw))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "<script>alert(1)</script>" not in report
    assert "<img src=x>" not in report


def test_ui_files_are_present_and_no_remote_frontend_assets():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert 'id="view-overview"' in html
    assert 'id="view-source"' in html
    assert 'id="view-indicators"' in html
    assert "/api/analyze" in js
    assert "https://" not in html.lower()
