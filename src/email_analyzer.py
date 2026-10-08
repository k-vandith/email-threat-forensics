"""Defensive email forensics: headers, phishing signals, auth interpretation, IOCs."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from email import message_from_string, policy
from pathlib import Path
from typing import Any

@dataclass
class EmailAnalysis:
    subject: str = ""
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    originating_ip: str | None = None
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"
    threat_score: float = 0.0
    phishing_indicators: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    timeline: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)

def parse_email(raw: str) -> EmailAnalysis:
    msg = message_from_string(raw, policy=policy.default)
    analysis = EmailAnalysis()
    analysis.subject = msg.get("Subject", "")
    analysis.sender = msg.get("From", "")
    to = msg.get("To", "")
    analysis.recipients = [x.strip() for x in to.split(",") if x.strip()]
    received = msg.get_all("Received", [])
    for h in reversed(received or []):
        ips = IP_RE.findall(h)
        if ips:
            analysis.originating_ip = ips[0]
            break
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content() or ""
        except Exception:
            body = str(msg.get_payload())
    full = raw + "\n" + body
    analysis.urls = list(dict.fromkeys(URL_RE.findall(full)))
    analysis.domains = list(dict.fromkeys(DOMAIN_RE.findall(analysis.sender + " " + " ".join(analysis.urls))))
    auth = msg.get("Authentication-Results", "") + " " + msg.get("Received-SPF", "")
    if re.search(r"spf=pass", auth, re.I):
        analysis.spf = "pass"
    elif re.search(r"spf=fail", auth, re.I):
        analysis.spf = "fail"
    if re.search(r"dkim=pass", auth, re.I):
        analysis.dkim = "pass"
    elif re.search(r"dkim=fail", auth, re.I):
        analysis.dkim = "fail"
    if re.search(r"dmarc=pass", auth, re.I):
        analysis.dmarc = "pass"
    elif re.search(r"dmarc=fail", auth, re.I):
        analysis.dmarc = "fail"
    score = 0.0
    if analysis.spf == "fail":
        analysis.phishing_indicators.append("SPF fail")
        score += 0.25
    if analysis.dkim == "fail":
        analysis.phishing_indicators.append("DKIM fail")
        score += 0.2
    if re.search(r"urgent|verify your account|password.*expire|click here", body + analysis.subject, re.I):
        analysis.phishing_indicators.append("Urgent language / credential bait")
        score += 0.2
    if any("bit.ly" in u or "tinyurl" in u for u in analysis.urls):
        analysis.phishing_indicators.append("URL shortener")
        score += 0.15
    analysis.threat_score = min(1.0, score)
    analysis.iocs = list(dict.fromkeys(
        ([analysis.originating_ip] if analysis.originating_ip else [])
        + analysis.urls
        + analysis.domains
    ))
    date = msg.get("Date", "")
    if date:
        analysis.timeline.append(f"Date header: {date}")
    if analysis.originating_ip:
        analysis.timeline.append(f"Originating IP: {analysis.originating_ip}")
    return analysis

def analyze_eml_file(path: Path) -> EmailAnalysis:
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_email(raw)
