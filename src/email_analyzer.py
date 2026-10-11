"""Defensive email forensics: headers, phishing signals, auth interpretation, IOCs."""
from __future__ import annotations

import ipaddress
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
    originating_ip_trust: str = "unverified"
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


URL_RE = re.compile(r"""https?://[^\s<>"']+""", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
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


def _received_spf_claims(values: list[str]) -> list[str]:
    """Extract the leading pass/fail result from every Received-SPF header."""
    claims: list[str] = []
    for value in values:
        match = re.match(r"^\s*(pass|fail)\b", value, re.I)
        if match:
            claims.append(match.group(1).lower())
    return claims


def _claim_status(method: str, auth_results: str, received_spf: list[str] | None = None) -> str:
    """Interpret explicit header claims conservatively: any explicit fail wins."""
    claims = re.findall(rf"\b{re.escape(method)}\s*=\s*(pass|fail)\b", auth_results, re.I)
    if method.lower() == "spf":
        claims.extend(_received_spf_claims(received_spf or []))
    normalized = [claim.lower() for claim in claims]
    if "fail" in normalized:
        return "fail"
    if "pass" in normalized:
        return "pass"
    return "unknown"


def _valid_ip_matches(text: str) -> list[str]:
    """Return syntactically valid IPv4 candidates from untrusted message text."""
    valid: list[str] = []
    for value in IP_RE.findall(text):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        valid.append(value)
    return valid


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
        ips = _valid_ip_matches(str(header))
        if ips:
            analysis.originating_ip = ips[0]
            analysis.originating_ip_trust = "untrusted_received_header_claim"
            break

    body_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment" or part.get_filename():
                # Some real-world messages specify a filename without a Content-Disposition
                # header. Do not treat those attached documents as the message body.
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
        body = "\n".join(body_parts)
    else:
        try:
            content = msg.get_content()
            body = content if isinstance(content, str) else content.decode("utf-8", errors="replace")
        except Exception:
            body = str(msg.get_payload())

    # Search the decoded message body and top-level headers, not the raw MIME source:
    # otherwise plain-text attachments can be misreported as the sender's lure.
    header_text = "\n".join(f"{name}: {value}" for name, value in msg.items())
    full = header_text + "\n" + body
    analysis.urls = _extract_urls(full)
    analysis.domains = list(dict.fromkeys(DOMAIN_RE.findall(full)))

    auth_values = [str(value) for value in (msg.get_all("Authentication-Results", []) or [])]
    auth_results = " ".join(auth_values)
    received_spf = [str(value) for value in (msg.get_all("Received-SPF", []) or [])]
    if auth_values or received_spf:
        analysis.anomalies.append(
            "Email authentication headers are unverified claims until their trusted receiving-server boundary is confirmed."
        )
    for method in ("spf", "dkim", "dmarc"):
        statuses = re.findall(rf"\b{method}\s*=\s*(pass|fail)\b", auth_results, re.I)
        if method == "spf":
            statuses.extend(_received_spf_claims(received_spf))
        normalized = [value.lower() for value in statuses]
        if "pass" in normalized and "fail" in normalized:
            analysis.anomalies.append(
                f"Conflicting {method.upper()} header claims; verify the trusted authentication boundary."
            )

    analysis.spf = _claim_status("spf", auth_results, received_spf)
    analysis.dkim = _claim_status("dkim", auth_results)
    analysis.dmarc = _claim_status("dmarc", auth_results)

    score = 0.0
    # Raw EML files do not prove which mail server inserted these headers.
    # Preserve the claims for analyst review, but never let unauthenticated
    # authentication headers determine the numeric triage score.
    if analysis.spf == "fail":
        analysis.phishing_indicators.append("SPF fail (unverified header claim)")
    if analysis.dkim == "fail":
        analysis.phishing_indicators.append("DKIM fail (unverified header claim)")
    if analysis.dmarc == "fail":
        analysis.phishing_indicators.append("DMARC fail (unverified header claim)")
    if re.search(r"urgent|verify your account|password.*expire|click here", body + analysis.subject, re.I):
        analysis.phishing_indicators.append("Urgent language / credential bait")
        score += 0.2
    if any(_has_shortener_host(url) for url in analysis.urls):
        analysis.phishing_indicators.append("URL shortener")
        score += 0.15
    analysis.threat_score = min(1.0, score)

    all_ips = list(dict.fromkeys(_valid_ip_matches(full)))
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
