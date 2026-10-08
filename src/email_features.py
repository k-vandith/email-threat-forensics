"""Email forensics extras: hop tracing, offline GeoIP, sklearn phishing, mbox, reports."""
from __future__ import annotations
import mailbox, re
from dataclasses import dataclass, field
from email import message_from_string, policy
from pathlib import Path
from typing import Any
from src.email_analyzer import parse_email, EmailAnalysis

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_OFFLINE_GEO = {"8.8.8.8": {"country": "US", "city": "Mountain View", "org": "Google"}, "1.1.1.1": {"country": "AU", "city": "Sydney", "org": "Cloudflare"}, "10.0.0.1": {"country": "PRIVATE", "city": "RFC1918", "org": "local"}}

@dataclass
class Hop:
    order: int
    raw: str
    ip: str | None = None
    geo: dict[str, str] = field(default_factory=dict)

def trace_hops(raw: str) -> list[Hop]:
    msg = message_from_string(raw, policy=policy.default)
    received = msg.get_all("Received", []) or []
    hops = []
    for i, h in enumerate(received):
        ips = IP_RE.findall(h)
        ip = ips[0] if ips else None
        geo = dict(_OFFLINE_GEO.get(ip or "", {}))
        if ip and not geo:
            geo = {"country": "PRIVATE", "city": "RFC1918", "org": "local"} if ip.startswith(("10.", "192.168.", "172.")) else {"country": "UNKNOWN", "city": "UNKNOWN", "org": "offline_db"}
        hops.append(Hop(order=i, raw=h[:300], ip=ip, geo=geo))
    return hops

def offline_geoip(ip: str) -> dict[str, str]:
    if ip in _OFFLINE_GEO: return dict(_OFFLINE_GEO[ip])
    if ip.startswith(("10.", "192.168.", "172.")): return {"country": "PRIVATE", "city": "RFC1918", "org": "local"}
    return {"country": "UNKNOWN", "city": "UNKNOWN", "org": "offline_db"}

def analyze_mbox(path: Path, limit: int = 50) -> list[EmailAnalysis]:
    results = []
    for i, msg in enumerate(mailbox.mbox(str(path))):
        if i >= limit: break
        results.append(parse_email(msg.as_string()))
    return results

def export_html_report(analysis: EmailAnalysis, hops: list[Hop] | None = None) -> str:
    hop_rows = "".join(f"<tr><td>{h.order}</td><td>{h.ip}</td><td>{h.geo}</td></tr>" for h in (hops or []))
    return f"<!DOCTYPE html><html><body><h1>Email Threat Report</h1><p>Subject: {analysis.subject}</p><p>Threat score: {analysis.threat_score}</p><h2>Hops</h2><table>{hop_rows}</table></body></html>"

def hops_geojson_points(hops: list[Hop]) -> dict[str, Any]:
    coords = {"US": [-122.08, 37.42], "AU": [151.2, -33.8], "PRIVATE": [0, 0], "UNKNOWN": [10, 10]}
    features = []
    for h in hops:
        if not h.ip: continue
        c = coords.get(h.geo.get("country", "UNKNOWN"), [10, 10])
        features.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": c}, "properties": {"ip": h.ip, "order": h.order, **h.geo}})
    return {"type": "FeatureCollection", "features": features}
