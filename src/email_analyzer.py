"""Defensive email forensics: headers, phishing signals, auth interpretation, IOCs."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string, policy
from email.utils import formataddr, getaddresses
from pathlib import Path
from urllib.parse import urlsplit


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


URL_RE = re.compile(r"https?://[^\\s<>\\"']+", re.I)
IP_RE = re.compile(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")
DOMAIN_RE = re.compile(r"\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}\\b", re.I)
SHORTENER_HOSTS = {"bit.ly", "tinyurl.com"}


def _trim_url(url: str) -> str:
    """Drop prose punctuation without stripping balanced URL parentheses."""
    url = url.rstrip(".,;:!?")
    pairs = ((")", "("), ("]", "["), ("}", "{"))
    changed = True
    while changed:
        changed = False
        for closing, opening in pairs:
            if url.endswith(closing) and url.count(closing) > url.count(opening):
                url = url[:-1]
                changed = True
    return url


def _extract_urls(text: str) -> list[str]:
    return list(dict.fromkeys(
        cleaned for match in URL_RE.findall(text)
        if (cleaned := _trim_url(match))
    ))


def _claim_status(method: str, auth_results: str, received_spf: str = "") -> str:
    """Interpret explicit header claims conservatively: any explicit fail wins."""
    claims = re.findall(rf"\\b{re.escape(method)}\\s*=\\s*(pass|fail)\\b", auth_results, re.I)
    if method.lower() == "spf":
        claims.extend(re.findall(r"^\\s*(pass|fail)\\b", received_spf, re.I | re.M))
    normalized = [claim.lower() for claim in claims]
    if "fail" in normalized:
        return "fail"
    if "pass" in normalized:
        return "pass"
    return "unknown"


def _has_shortener_host(url: str) -> bool:
    try:
        hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    return hostname in SHORTENER_HOSTS


def parse_email(raw: str) -> EmailAnalysis:
    msg = message_from_string(raw, policy=policy.default)
    analysis = EmailAnalysis()
    analysis.subject = str(msg.get("Subject", ""))
    analysis.sender = str(msg.get("From", ""))
    recipient_headers = [str(value) for value in (msg.get_all("To", []) or [])]
    analysis.recipients = [
        formataddr((name, address)) if name else address
        for name, address in getaddresses(recipient_headers)
        if address
    ]

    received = msg.get_all("Received", []) or []
    for header in reversed(received):
        ips = IP_RE.findall(str(header))
        if ips:
            analysis.originating_ip = ips[0]
            break

    body_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if isinstance(content, bytes):
                content = content.decode(part.get_content_charset() or "utf-8", errors="replace")
            if isinstance(content, str):
                body_parts.append(content)
        body = "\\n".join(body_parts)
    else:
        try:
            content = msg.get_content()
            body = content if isinstance(content, str) else content.decode("utf-8", errors="replace")
        except Exception:
            body = str(msg.get_payload())

    full = raw + "\\n" + body
    analysis.urls = _extract_urls(full)
    analysis.domains = list(dict.fromkeys(DOMAIN_RE.findall(full)))

    auth_values = [str(value) for value in (msg.get_all("Authentication-Results", []) or [])]
    auth_results = " ".join(auth_values)
    received_spf = " ".join(str(value) for value in (msg.get_all("Received-SPF", []) or []))
    for method in ("spf", "dkim", "dmarc"):
        statuses = re.findall(rf"\\b{method}\\s*=\\s*(pass|fail)\\b", auth_results, re.I)
        if method == "spf":
            statuses.extend(re.findall(r"^\\s*(pass|fail)\\b", received_spf, re.I | re.M))
        normalized = [value.lower() for value in statuses]
        if "pass" in normalized and "fail" in normalized:
            analysis.anomalies.append(
                f"Conflicting {method.upper()} header claims; verify the trusted authentication boundary."
            )

    analysis.spf = _claim_status("spf", auth_results, received_spf)
    analysis.dkim = _claim_status("dkim", auth_results)
    analysis.dmarc = _claim_status("dmarc", auth_results)

    score = 0.0
    if analysis.spf == "fail":
        analysis.phishing_indicators.append("SPF fail")
        score += 0.25
    if analysis.dkim == "fail":
        analysis.phishing_indicators.append("DKIM fail")
        score += 0.2
    if analysis.dmarc == "fail":
        analysis.phishing_indicators.append("DMARC fail")
        score += 0.15
    if re.search(r"urgent|verify your account|password.*expire|click here", body + analysis.subject, re.I):
        analysis.phishing_indicators.append("Urgent language / credential bait")
        score += 0.2
    if any(_has_shortener_host(url) for url in analysis.urls):
        analysis.phishing_indicators.append("URL shortener")
        score += 0.15
    analysis.threat_score = min(1.0, score)

    all_ips = list(dict.fromkeys(IP_RE.findall(full)))
    analysis.iocs = list(dict.fromkeys(
        ([analysis.originating_ip] if analysis.originating_ip else [])
        + all_ips
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
