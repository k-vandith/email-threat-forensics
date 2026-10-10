"""Local-only HTTP workspace for SignalTrace; email content never leaves this process."""
from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict
from email import message_from_string, policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from src.email_analyzer import parse_email
from src.email_features import export_html_report, trace_hops

ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "web"
SAMPLE_PATH = ROOT / "data" / "sample" / "phishing_sample.eml"
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/mark.svg": ("mark.svg", "image/svg+xml"),
}


def analyze_message(raw: str, filename: str = "message.eml") -> dict[str, Any]:
    """Analyze a supplied message without network requests or file persistence."""
    if not isinstance(raw, str):
        raise ValueError("Message content must be text.")
    size = len(raw.encode("utf-8"))
    if size == 0:
        raise ValueError("The selected message is empty.")
    if size > MAX_MESSAGE_BYTES:
        raise ValueError("Messages must be smaller than 2 MB.")
    clean_name = Path(str(filename)).name[:180] or "message.eml"
    analysis = parse_email(raw)
    hops = trace_hops(raw)
    message = message_from_string(raw, policy=policy.default)
    headers = [{"name": name, "value": str(value)} for name, value in message.items()]
    score = round(float(analysis.threat_score), 2)
    band = "critical" if score >= 0.75 else "high" if score >= 0.5 else "guarded" if score >= 0.25 else "low"
    return {
        "filename": clean_name,
        "size_bytes": size,
        "subject": analysis.subject or "(no subject)",
        "sender": analysis.sender or "Unknown sender",
        "recipients": analysis.recipients,
        "date": str(message.get("Date", "")),
        "reply_to": str(message.get("Reply-To", "")),
        "message_id": str(message.get("Message-ID", "")),
        "originating_ip": analysis.originating_ip,
        "domains": analysis.domains,
        "urls": analysis.urls,
        "headers": headers,
        "spf": analysis.spf,
        "dkim": analysis.dkim,
        "dmarc": analysis.dmarc,
        "threat_score": score,
        "risk_band": band,
        "phishing_indicators": analysis.phishing_indicators,
        "iocs": analysis.iocs,
        "timeline": analysis.timeline,
        "anomalies": analysis.anomalies,
        "hops": [asdict(hop) for hop in hops],
    }


class SignalTraceHandler(BaseHTTPRequestHandler):
    """Small allow-listed static server plus two local analysis endpoints."""

    server_version = "SignalTraceLocal/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        logging.info("%s - %s", self.client_address[0], fmt % args)

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
        )
        super().end_headers()

    def _send(self, status: int, content: bytes, content_type: str, attachment: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        if attachment:
            self.send_header("Content-Disposition", 'attachment; filename="' + attachment.replace('"', "") + '"')
        self.end_headers()
        self.wfile.write(content)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, content, "application/json; charset=utf-8")

    def do_GET(self) -> None:
        route = urlsplit(self.path).path
        if route == "/api/health":
            self._json(200, {"ok": True, "service": "SignalTrace Local", "network_lookups": False})
            return
        if route == "/api/sample":
            try:
                raw = SAMPLE_PATH.read_text(encoding="utf-8", errors="replace")
            except OSError:
                self._json(500, {"error": "The bundled sample message is unavailable."})
                return
            self._json(200, {"filename": SAMPLE_PATH.name, "raw": raw})
            return
        static = STATIC_FILES.get(route)
        if static:
            filename, content_type = static
            try:
                content = (WEB_DIR / filename).read_bytes()
            except OSError:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
                return
            self._send(200, content, content_type)
            return
        self._json(404, {"error": "Route not found."})

    def do_POST(self) -> None:
        route = urlsplit(self.path).path
        if route not in {"/api/analyze", "/api/report"}:
            self._json(404, {"error": "Route not found."})
            return
        try:
            raw_length = self.headers.get("Content-Length", "")
            length = int(raw_length)
            if length < 1:
                self._json(400, {"error": "Request body is empty."})
                return
            if length > MAX_MESSAGE_BYTES + 32_000:
                self._json(413, {"error": "Upload exceeds the 2 MB message limit."})
                return
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
            raw = payload.get("raw")
            filename = payload.get("filename", "message.eml")
            result = analyze_message(raw, filename)
            if route == "/api/analyze":
                self._json(200, result)
                return
            hops = trace_hops(raw)
            from src.email_analyzer import parse_email

            report = export_html_report(parse_email(raw), hops)
            self._send(
                200,
                report.encode("utf-8"),
                "text/html; charset=utf-8",
                "signaltrace-evidence-report.html",
            )
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError, TypeError, ValueError) as exc:
            self._json(400, {"error": str(exc) or "Invalid analysis request."})
        except BrokenPipeError:
            return
        except Exception:
            logging.exception("Analysis request failed")
            self._json(500, {"error": "The message could not be analyzed. Check the file and try again."})


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Launch the local SignalTrace email-forensics workspace.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    server = ThreadingHTTPServer((args.host, args.port), SignalTraceHandler)
    url = "http://%s:%d" % (args.host, args.port)
    print("SignalTrace is ready at " + url)
    print("Local analysis only: no DNS, geolocation, or external API calls are made.")
    if not args.no_browser and args.host in {"127.0.0.1", "localhost"}:
        import webbrowser

        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SignalTrace.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
