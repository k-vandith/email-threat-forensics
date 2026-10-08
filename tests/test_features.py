from src.email_features import trace_hops, offline_geoip, export_html_report
from src.email_analyzer import parse_email
SAMPLE = "From: a@b.com\nTo: c@d.com\nSubject: Hello\nReceived: from x (8.8.8.8)\n\nHi"
def test_hops():
    assert isinstance(trace_hops(SAMPLE), list)
def test_geo():
    assert offline_geoip("8.8.8.8")["country"] == "US"
def test_report():
    assert "Threat" in export_html_report(parse_email(SAMPLE))
