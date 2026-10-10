# SignalTrace — Email Threat Forensics

**A privacy-first email examination desk for local investigation of .eml evidence.** SignalTrace parses message headers, authentication-result claims, routing hops, URLs and domains, then presents its evidence in a purpose-built HTML/CSS/JavaScript workspace.

The browser UI is served by a small Python standard-library HTTP server. Your message is analyzed on your own machine; the app has no external API integrations and does not perform DNS, IP reputation, URL reputation or live geolocation lookups.

## What it does

- **Examine a message envelope:** subject, sender, recipients, declared date, message ID and origin IP.
- **Review authentication claims:** interpret SPF, DKIM and DMARC outcomes that are already present in the message headers. These are not independently verified by the app.
- **Follow the Received trail:** list parsed mail hops in header order and display offline labels only.
- **Explain local signals:** show the configured heuristic flags and a bounded risk score.
- **Inventory IOCs:** deduplicate observed IPs, URLs and domains; filter and copy values; export JSON or CSV.
- **Preserve evidence:** inspect the raw message, browse parsed headers and export a self-contained HTML evidence report.
- **Stay local:** no account, API key, GPU, external fonts, analytics beacon or network enrichment is needed.

## Start

Python 3.11 or newer is recommended. From a terminal:

    git clone https://github.com/k-vandith/email-threat-forensics.git
    cd email-threat-forensics
    python run.py

Open http://127.0.0.1:8765 if the browser does not open automatically. To use another port:

    python run.py --port 9000

To run without launching a browser:

    python run.py --no-browser

The server binds to 127.0.0.1 by default. Avoid exposing the service on an untrusted network: messages are sensitive and this small local workstation is not an authenticated multi-user service.

## Workflow

1. Open the bundled training message, or choose **Import .eml** to inspect a local .eml / .txt message.
2. Read the risk score and the individual signals. The score is an explainable heuristic, not a probability of compromise.
3. Review authentication claims and the Received-header trail.
4. Open **Message source** to inspect the original text and parsed headers.
5. Open **IOC register** to filter the extracted evidence, copy values, or export CSV / JSON.
6. Export a self-contained HTML report when a shareable summary is needed.

A sample case is restored from data/sample/phishing_sample.eml on demand. Its values are illustrative. The sample uses documentation-only IP space and reserved example domains; it is not evidence of a live incident.

## Heuristic model and limits

Current score weights are deliberately transparent: SPF fail +0.25, DKIM fail +0.20, DMARC fail +0.15, urgent / credential-bait language +0.20, and a recognized URL shortener +0.15, capped at 1.00. A message can still be malicious if none of these rules fire. A low score is not a guarantee of safety.

- Authentication outcomes are read from headers supplied with the message and may be forged.
- IP and domain values are extracted heuristically; validity, ownership and reputation are not verified.
- URL extraction is not a browser, redirect resolver or detonation sandbox. SignalTrace does not open links.
- The hop labels are offline placeholders, not authoritative geolocation.
- Attachments are not executed or detonated; no malware verdict is produced.
- Preserve the original message independently when chain-of-custody or legal requirements apply.

## Privacy and security

- Input is processed in memory by the local process and is not intentionally written to an upload directory.
- Requests are capped at 2 MB per message.
- The browser interface uses a restrictive Content Security Policy, disables automatic external assets and renders message-derived content as text.
- HTML reports escape message-derived values to prevent them from becoming active markup.
- Do not commit genuine mailbox exports or production message contents to a public repository.

## Development and tests

Runtime code uses the Python standard library. For development checks:

    python -m venv .venv
    # Windows PowerShell: .venv\Scripts\Activate.ps1
    # macOS / Linux: source .venv/bin/activate
    python -m pip install -r requirements-dev.txt
    ruff check src run.py tests
    bandit -q -r src run.py -ll
    pip-audit -r requirements.txt --progress-spinner off
    pytest -q

The GitHub Actions workflow runs lint, Bandit, dependency audit and tests for pull requests and pushes to main.

## Project map

    src/email_analyzer.py    Header parsing, IOC extraction and heuristic scoring
    src/email_features.py    Received-hop parsing, offline labels and safe HTML reports
    src/webapp.py            Local HTTP server and JSON analysis endpoints
    web/index.html           Accessible workspace layout
    web/styles.css           Responsive evidence-desk visual system
    web/app.js               Browser interactions and evidence exports
    data/sample/             Non-production training fixture
    tests/                   Parser, report security and UI smoke tests

## License

MIT. Defensive email forensics and education.
