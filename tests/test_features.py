from src.email_features import (
    Hop,
    hops_geojson_points,
    trace_hops,
    offline_geoip,
    export_html_report,
)
from src.email_analyzer import parse_email

SAMPLE = "From: a@b.com\nTo: c@d.com\nSubject: Hello\nReceived: from x (8.8.8.8)\n\nHi"


def test_hops():
    assert isinstance(trace_hops(SAMPLE), list)


def test_public_ip_geo_is_unknown_without_a_verified_offline_database():
    assert offline_geoip("8.8.8.8")["country"] == "UNKNOWN"
    assert offline_geoip("1.1.1.1")["city"] == "UNKNOWN"
    assert offline_geoip("10.0.0.1")["country"] == "PRIVATE"


def test_report():
    assert "Threat" in export_html_report(parse_email(SAMPLE))


def test_received_headers_are_ordered_oldest_to_newest():
    raw = (
        "From: sender@example.test\n"
        "Received: from newest-relay (203.0.113.10) by mx.example.test\n"
        "Received: from origin (172.31.8.2) by newest-relay\n\n"
        "body"
    )

    hops = trace_hops(raw)

    assert [hop.ip for hop in hops] == ["172.31.8.2", "203.0.113.10"]
    assert hops[0].geo["country"] == "PRIVATE"


def test_private_ipv4_range_checks_the_rfc1918_boundaries():
    assert offline_geoip("172.16.0.1")["country"] == "PRIVATE"
    assert offline_geoip("172.31.255.254")["country"] == "PRIVATE"
    assert offline_geoip("172.32.0.1")["country"] == "UNKNOWN"
    assert offline_geoip("172.999.0.1")["country"] == "UNKNOWN"


def test_geojson_omits_public_ips_without_verified_coordinates():
    public = Hop(order=0, raw="public", ip="8.8.8.8", geo=offline_geoip("8.8.8.8"))
    documentation = Hop(order=1, raw="documentation", ip="203.0.113.10", geo=offline_geoip("203.0.113.10"))

    result = hops_geojson_points([public, documentation])

    assert result["features"] == []
