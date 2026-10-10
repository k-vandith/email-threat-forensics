<p align="center">
  <img src="web/mark.svg" alt="SignalTrace logo" width="92" />
</p>

<h1 align="center">SignalTrace</h1>
<p align="center">
  <strong>Follow the headers. Understand the signals. Preserve the evidence.</strong><br />
  A local-first email threat investigation workspace for analysts, defenders, and students.
</p>

<p align="center">
  <a href="https://github.com/k-vandith/email-threat-forensics/actions/workflows/tests.yml"><img src="https://github.com/k-vandith/email-threat-forensics/actions/workflows/tests.yml/badge.svg?branch=main" alt="Tests" /></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/UI-HTML%20%2F%20CSS%20%2F%20JS-e0a75a?logo=javascript&logoColor=171b17" alt="HTML CSS JavaScript" />
  <img src="https://img.shields.io/badge/processing-local--first-5b8066?labelColor=263a31" alt="Local-first processing" />
  <img src="https://img.shields.io/badge/license-MIT-64748b" alt="MIT License" />
</p>

---

## What is SignalTrace?

SignalTrace is a local-first evidence desk for **Email Threat Forensics**. It parses .eml or plain-text message files, summarises sender and recipient context, interprets authentication-result claims already present in the headers, traces Received hops, and extracts URLs, domains, and IP addresses for review.

- **Read the message:** inspect the subject, sender, recipient, declared date, message ID, and available origin IP.
- **Understand the signals:** see SPF, DKIM, and DMARC header claims alongside transparent phishing-rule indicators and a bounded heuristic score.
- **Follow the route:** review the observed Received-header chain without fabricated live geolocation.
- **Preserve useful evidence:** inspect raw source and parsed headers, copy individual indicators, and export CSV, JSON, or a standalone HTML report.
- **Keep the investigation local:** the app has no analytics beacon, paid API dependency, external analysis service, or automatic URL-opening behavior.

SignalTrace is a **rule-based triage aid**, not a mail gateway, a verdict that a message is malicious, or a substitute for incident-response procedures.

## Quick start

Python 3.11 or newer is recommended. Runtime code uses the Python standard library; no paid API key, cloud service, or GPU is required.

~~~bash
git clone https://github.com/k-vandith/email-threat-forensics.git
cd email-threat-forensics
python -m venv .venv
~~~

Activate the virtual environment and start the workspace:

**Windows · PowerShell**

~~~powershell
.venv\Scripts\Activate.ps1
python run.py
~~~

**macOS · Linux**

~~~bash
source .venv/bin/activate
python run.py
~~~

Open **http://127.0.0.1:8765**. If the browser does not open automatically, enter the address yourself.

To use a different port or suppress automatic browser launch:

~~~bash
python run.py --port 9000
python run.py --no-browser
~~~

## Try it in five steps

1. Start SignalTrace and review the bundled training case, phishing_sample.eml.
2. Read the overview: heuristic score, authentication claims, sender/recipient information, and configured risk signals.
3. Inspect the **mail-hop trail** to see Received headers in message order.
4. Open **Message source** to inspect the raw message and its parsed header inventory.
5. Open the **IOC register** to filter or copy values, export CSV/JSON, or use **Export evidence** for a self-contained HTML report.

Use **Import .eml** to choose a local .eml or .txt file. **Restore sample case** returns to the bundled demonstration fixture.

The sample case uses illustrative domains and a documentation-only IP address. It is training data, not evidence of a live incident.

## Supported inputs and outputs

| Type | Formats | What SignalTrace does |
|---|---|---|
| Email message | .eml, .txt | Reads message headers and supported text content; extracts sender/recipient context, URLs, domains and observable indicators. |
| Authentication claims | Authentication-Results, Received-SPF | Interprets explicit SPF, DKIM and DMARC results already written into the message. It does not independently validate these claims. |
| Mail routing | Received headers | Lists captured header hops and extracts visible IPv4-looking values. Parsing is heuristic; IP validity and ownership are not confirmed. |
| Evidence export | HTML | Generates a self-contained report with the score, indicators, authentication claims, and parsed hops. |
| IOC export | CSV, JSON | Exports observed indicator values and contextual types for offline review or follow-on workflows. |

Messages are limited to **2 MB** per analysis request. Unsupported or malformed input may produce an error or incomplete results; preserve the original message separately when chain-of-custody requirements apply.

## Architecture

~~~mermaid
flowchart TD
    User[Analyst] --> Browser[SignalTrace HTML / CSS / JavaScript]
    Browser --> Import[Import local EML / TXT]
    Import --> Local[Local Python HTTP server]
    Local --> Parser[Email header and body parser]
    Parser --> Auth[SPF / DKIM / DMARC header claims]
    Parser --> Hops[Received-hop and origin extraction]
    Parser --> IOCs[URL, domain and IP extraction]
    Auth --> Scoring[Explainable heuristic scoring]
    Hops --> Summary[Case overview and evidence views]
    IOCs --> Summary
    Scoring --> Summary
    Summary --> Export[HTML report / CSV / JSON]
~~~

## How to read the results

- **SPF / DKIM / DMARC:** these are interpreted from the submitted message's authentication headers. Headers can be forged, absent, or produced by an unrelated hop. Unknown means the expected explicit result was not detected.
- **Received hops:** displayed in header order as represented in the source email. They are useful leads, not proof of the full trusted mail route.
- **URLs and domains:** extracted as text for review. SignalTrace does not navigate to them, resolve redirects, or query reputation services.
- **Indicator register:** deduplicated observed strings (IP-like values, URLs, and domains). Extraction alone does not establish that a value is malicious.
- **Risk score:** a capped, explainable heuristic from selected indicators. It is not a probability that a message is phishing or a measure of financial or operational impact.

### Current heuristic weights

| Signal | Score contribution |
|---|---:|
| SPF failure claim | +0.25 |
| DKIM failure claim | +0.20 |
| DMARC failure claim | +0.15 |
| Urgent or credential-bait language | +0.20 |
| Recognised URL shortener (bit.ly / tinyurl) | +0.15 |
| Maximum score | 1.00 |

Weights are rule-based and deliberately simple. A message can be malicious when none of the rules match; conversely, a match may have a legitimate explanation. Review the evidence and surrounding context before acting.

## Privacy and security

- Message analysis runs locally in the Python process. The app does not send message content to a remote analysis endpoint.
- The local server binds to 127.0.0.1 by default and uses a content security policy for its browser UI.
- Message-derived values are inserted into the UI as text. HTML report values are escaped to avoid turning untrusted message content into active markup.
- Requests are size-limited to reduce accidental or abusive oversized submissions.
- No live DNS, URL reputation, IP reputation, or geolocation requests are made.
- Do not expose this simple local workspace to untrusted networks. It has no user authentication or multi-user access controls.
- Email evidence can contain personal and confidential information. Do not commit real mailbox exports to a public repository, and review reports before sharing them.

## Limitations

- Authentication results are read from message headers; they are not independently verified against DNS or a trusted mail gateway.
- URL extraction is heuristic. The app does not dereference links, follow redirects, inspect web pages, or detonate attachments.
- Hop labels are offline placeholders, not authoritative geolocation.
- IP/domain extraction does not verify validity, ownership, or reputation.
- Attachments are not executed or scanned, and no malware verdict is produced.
- The score is not a calibrated probability or a replacement for secure-email gateway analysis, sandboxing, or incident-response review.

## Tests and development

Install the development tools:

~~~bash
python -m pip install -r requirements-dev.txt
~~~

Run the checks:

~~~bash
ruff check src run.py tests
bandit -q -r src run.py -ll
pip-audit -r requirements.txt --progress-spinner off
pytest -q
~~~

The GitHub Actions workflow runs Ruff, Bandit, dependency auditing, and the test suite for pull requests and pushes to main.

## Project map

~~~text
src/
  app.py                 Compatibility entry point
  webapp.py              Local HTTP server and analysis endpoints
  email_analyzer.py      Header parsing, IOC extraction and scoring
  email_features.py      Received-hop parsing and safe HTML reports
web/
  index.html             SignalTrace case workspace
  styles.css             Responsive evidence-desk design system
  app.js                 Browser interactions and export actions
  mark.svg               SignalTrace product mark
data/sample/
  phishing_sample.eml    Fictional training message
tests/
  test_email.py          Message parsing and risk-signal checks
  test_features.py       Hop parsing and report tests
  test_webapp.py         Local API and report-safety tests
  test_ui_smoke.py       Entry-point and browser-asset smoke tests
~~~

## License

MIT. See [LICENSE](LICENSE).
