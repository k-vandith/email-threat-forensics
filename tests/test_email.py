from pathlib import Path
import base64

from src.email_analyzer import analyze_eml_file, parse_email


def test_phishing_sample():
    p = Path(__file__).resolve().parents[1] / "data" / "sample" / "phishing_sample.eml"
    if not p.exists():
        import runpy
        runpy.run_path(str(p.parents[2] / "scripts" / "generate_demo_data.py"))
    a = analyze_eml_file(p)
    assert a.threat_score > 0.3
    assert a.spf == "fail"
    assert any("bit.ly" in u for u in a.urls)


def test_standard_received_spf_header_failure_is_detected():
    analysis = parse_email(
        "From: sender@example.test\n"
        "Received-SPF: fail (example.test does not designate 203.0.113.8)\n"
        "Subject: Update\n\n"
        "Please review."
    )

    assert analysis.spf == "fail"
    assert "SPF fail" in analysis.phishing_indicators


def test_conflicting_authentication_claims_never_resolve_to_pass():
    analysis = parse_email(
        "From: sender@example.test\n"
        "Authentication-Results: first.example; spf=pass; dkim=pass; dmarc=pass\n"
        "Authentication-Results: second.example; spf=fail; dkim=fail; dmarc=fail\n\n"
        "Hello."
    )

    assert analysis.spf == analysis.dkim == analysis.dmarc == "fail"
    assert len(analysis.anomalies) == 4
    assert any("unverified claims" in anomaly for anomaly in analysis.anomalies)


def test_extracts_bare_body_domains_all_ip_values_and_cleans_url_punctuation():
    analysis = parse_email(
        "From: Sender <sender@legit.example>\n"
        "Received: from mx (198.51.100.2)\n"
        "Subject: Link\n\n"
        "Visit https://example.test/login).\n"
        "Also check portal.attacker.example and 203.0.113.77.\n"
        "Not shorteners: https://mybit.ly.example/path and https://not-bit.ly.attacker.test/path"
    )

    assert "https://example.test/login" in analysis.urls
    assert "https://example.test/login)." not in analysis.urls
    assert "portal.attacker.example" in analysis.domains
    assert "198.51.100.2" in analysis.iocs
    assert "203.0.113.77" in analysis.iocs
    assert "portal.attacker.example" in analysis.iocs
    assert "URL shortener" not in analysis.phishing_indicators


def test_html_only_multipart_body_is_decoded_for_url_and_lure_detection():
    html_body = '<html><body>Verify your account <a href="https://bit.ly/login">continue</a></body></html>'
    encoded = base64.b64encode(html_body.encode("utf-8")).decode("ascii")
    raw = (
        "From: sender@example.test\n"
        "Subject: Review required\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/alternative; boundary="TRACEBOUNDARY"\n\n'
        "--TRACEBOUNDARY\n"
        "Content-Type: text/html; charset=utf-8\n"
        "Content-Transfer-Encoding: base64\n\n"
        + encoded
        + "\n--TRACEBOUNDARY--\n"
    )

    analysis = parse_email(raw)

    assert "https://bit.ly/login" in analysis.urls
    assert "Urgent language / credential bait" in analysis.phishing_indicators
    assert "URL shortener" in analysis.phishing_indicators


def test_to_header_with_comma_inside_display_name_parses_recipients():
    analysis = parse_email(
        'From: sender@example.test\n'
        'To: "Doe, Jane" <jane@example.test>, team@example.test\n'
        'Subject: Test\n\nHi'
    )

    assert len(analysis.recipients) == 2
    assert "jane@example.test" in analysis.recipients[0]
    assert analysis.recipients[1] == "team@example.test"

def test_all_received_spf_headers_contribute_to_status_and_conflict_detection():
    analysis = parse_email(
        "From: sender@example.test\n"
        "Received-SPF: pass (trusted.example: domain of sender@example.test designates 192.0.2.4)\n"
        "Received-SPF: fail (untrusted.example: domain of sender@example.test does not designate 192.0.2.4)\n"
        "Subject: Routine message\n\n"
        "Hello."
    )

    assert analysis.spf == "fail"
    assert any("Conflicting SPF" in anomaly for anomaly in analysis.anomalies)


def test_multipart_text_attachment_without_disposition_is_not_analyzed_as_body():
    raw = (
        "From: sender@example.test\n"
        "Subject: Routine message\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/mixed; boundary="TRACEBOUNDARY"\n\n'
        "--TRACEBOUNDARY\n"
        'Content-Type: text/plain; name="notice.txt"\n'
        "Content-Transfer-Encoding: 7bit\n\n"
        "URGENT: verify your account at https://attacker.example/attachment\n"
        "--TRACEBOUNDARY\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Ordinary status update.\n"
        "--TRACEBOUNDARY--\n"
    )

    analysis = parse_email(raw)

    assert "https://attacker.example/attachment" not in analysis.urls
    assert "attacker.example" not in analysis.domains
    assert "Urgent language / credential bait" not in analysis.phishing_indicators



def test_invalid_ipv4_in_received_header_is_not_reported_as_originating_ip():
    analysis = parse_email(
        "From: sender@example.test\n"
        "Received: from untrusted.example (999.999.999.999)\n"
        "Subject: Header validation\n\n"
        "Ordinary message."
    )

    assert analysis.originating_ip is None
    assert "999.999.999.999" not in analysis.iocs


def test_originating_ip_is_marked_as_an_untrusted_header_claim():
    analysis = parse_email(
        "From: sender@example.test\n"
        "Received: from relay.example (198.51.100.42)\n"
        "Subject: Header validation\n\n"
        "Ordinary message."
    )

    assert analysis.originating_ip == "198.51.100.42"
    assert any("untrusted Received header" in item for item in analysis.anomalies)



def test_hop_timeline_does_not_assign_geolocation_to_invalid_ip_text():
    from src.email_features import trace_hops

    hops = trace_hops(
        "From: sender@example.test\n"
        "Received: from untrusted.example (999.999.999.999)\n\n"
        "Hello"
    )

    assert len(hops) == 1
    assert hops[0].ip is None
    assert hops[0].geo == {}



def test_authentication_pass_header_is_disclosed_as_unverified_input():
    analysis = parse_email(
        "From: sender@example.test\n"
        "Authentication-Results: example.test; spf=pass; dkim=pass; dmarc=pass\n\n"
        "Routine message."
    )

    assert analysis.spf == analysis.dkim == analysis.dmarc == "pass"
    assert any("unverified claims" in anomaly for anomaly in analysis.anomalies)
