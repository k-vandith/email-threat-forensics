"""Email forensics extras: hop tracing, offline GeoIP, mbox and safe HTML reports."""
from __future__ import annotations
import html
import mailbox
import re
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
    for i, header in enumerate(received):
        ips = IP_RE.findall(header)
        ip = ips[0] if ips else None
        geo = dict(_OFFLINE_GEO.get(ip or "", {}))
        if ip and not geo:
            geo = {"country": "PRIVATE", "city": "RFC1918", "org": "local"} if ip.startswith(("10.", "192.168.", "172.")) else {"country": "UNKNOWN", "city": "UNKNOWN", "org": "offline_db"}
        hops.append(Hop(order=i, raw=str(header)[:300], ip=ip, geo=geo))
    return hops

def offline_geoip(ip: str) -> dict[str, str]:
    if ip in _OFFLINE_GEO:
        return dict(_OFFLINE_GEO[ip])
    if ip.startswith(("10.", "192.168.", "172.")):
        return {"country": "PRIVATE", "city": "RFC1918", "org": "local"}
    return {"country": "UNKNOWN", "city": "UNKNOWN", "org": "offline_db"}

def analyze_mbox(path: Path, limit: int = 50) -> list[EmailAnalysis]:
    results = []
    for i, msg in enumerate(mailbox.mbox(str(path))):
        if i >= limit:
            break
        results.append(parse_email(msg.as_string()))
    return results

def export_html_report(analysis: EmailAnalysis, hops: list[Hop] | None = None) -> str:
    """Return a self-contained report with every message-derived value HTML-escaped."""
    esc = html.escape
    hop_rows = "".join(
        "<tr><td>" + esc(str(h.order)) + "</td><td>" + esc(str(h.ip or "—")) + "</td><td>" +
        esc(", ".join(str(value) for value in h.geo.values()) or "Unknown; offline") + "</td><td>" +
        esc(h.raw) + "</td></tr>"
        for h in (hops or [])
    )
    indicator_rows = "".join("<li>" + esc(item) + "</li>" for item in (analysis.phishing_indicators or [])) or "<li>No configured signals were flagged.</li>"
    url_rows = "".join("<li><code>" + esc(url) + "</code></li>" for url in (analysis.urls or [])) or "<li>None</li>"
    ioc_rows = "".join("<li><code>" + esc(ioc) + "</code></li>" for ioc in (analysis.iocs or [])) or "<li>None</li>"
    subject = esc(analysis.subject or "(no subject)")
    sender = esc(analysis.sender or "Unknown sender")
    score = max(0.0, min(1.0, float(analysis.threat_score)))
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>SignalTrace evidence report</title><style>
:root{color-scheme:light}body{font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;max-width:920px;margin:36px auto;padding:0 22px;color:#26352c;background:#f5f2e9}
header,section{background:#fffdf8;border:1px solid #e2ddcf;border-radius:10px;padding:22px;margin:14px 0}
.kicker{font-size:11px;letter-spacing:.16em;color:#68776a;font-weight:800}h1{font-size:29px;letter-spacing:-.04em;margin:8px 0}h2{font-size:17px;margin:0 0 12px}p,li{overflow-wrap:anywhere}code{font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere}
.score{font-size:32px;font-weight:800;color:#a5483d}.muted{color:#737d72;font-size:12px}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #e7e1d5;text-align:left;vertical-align:top;padding:8px;font-size:12px;overflow-wrap:anywhere}th{color:#737d72}
</style></head><body><header><div class="kicker">SIGNALTRACE / LOCAL EVIDENCE EXPORT</div><h1>Email Threat Examination</h1><p><b>Subject:</b> """ + subject + """</p><p><b>Sender:</b> """ + sender + """</p><p class="score">""" + f"{score:.2f}" + """ / 1.00</p><p class="muted">Heuristic triage score. Not a verdict; authentication values are header claims and have not been independently verified.</p></header>
<section><h2>Configured signals</h2><ul>""" + indicator_rows + """</ul></section>
<section><h2>Authentication claims</h2><p>SPF: <b>""" + esc(analysis.spf) + """</b> · DKIM: <b>""" + esc(analysis.dkim) + """</b> · DMARC: <b>""" + esc(analysis.dmarc) + """</b></p></section>
<section><h2>Observed mail hops</h2><table><thead><tr><th>Order</th><th>IP</th><th>Offline label</th><th>Raw header</th></tr></thead><tbody>""" + hop_rows + """</tbody></table><p class="muted">No live geolocation or network lookups were performed.</p></section>
<section><h2>Extracted URLs</h2><ul>""" + url_rows + """</ul></section>
<section><h2>Indicator register</h2><ul>""" + ioc_rows + """</ul></section>
<footer class="muted">Generated locally by SignalTrace. Preserve the original .eml separately when evidentiary chain-of-custody matters.</footer></body></html>"""

def hops_geojson_points(hops: list[Hop]) -> dict[str, Any]:
    coords = {"US": [-122.08, 37.42], "AU": [151.2, -33.8], "PRIVATE": [0, 0], "UNKNOWN": [10, 10]}
    features = []
    for hop in hops:
        if not hop.ip:
            continue
        country = hop.geo.get("country", "UNKNOWN")
        point = coords.get(country, [10, 10])
        features.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": point}, "properties": {"ip": hop.ip, "order": hop.order, **hop.geo}})
    return {"type": "FeatureCollection", "features": features}
