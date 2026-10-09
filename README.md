# Email Threat Detection & Forensic Intelligence Platform

Offline email forensics toolkit for header analysis, SPF/DKIM/DMARC signals, URL extraction, and phishing-risk scoring.

## Problem Statement

Phishing and business-email compromise remain top enterprise threats. Analysts need a local tool to dissect `.eml` messages, score risk, and extract IOCs without uploading mail to third-party services.

## Overview

Parse email headers and bodies, evaluate authentication results, extract URLs/domains, and produce a risk score with explainable signals for investigators.

## Features

- **EML parsing** – headers, body, attachments metadata
- **Auth signals** – SPF / DKIM / DMARC result interpretation
- **URL extraction** – linked and obfuscated patterns
- **Phishing score** – weighted heuristic model
- **Streamlit UI** – upload and review workflow
- **Demo samples** – benign and phishing-like fixtures

## Architecture

```
┌─────────────┐     ┌────────────────┐     ┌─────────────┐
│  Streamlit  │────▶│ Email Analyzer │────▶│  Scoring    │
│     UI      │     │                │     │  engine     │
└─────────────┘     └───────┬────────┘     └─────────────┘
                            │
                     ┌──────▼──────┐
                     │  IOC export │
                     └─────────────┘
```

## Tech Stack

- Python 3.11+
- Streamlit
- Pandas
- Pydantic
- pytest

## Repository Structure

```
email-threat-forensics/
├── README.md
├── requirements.txt
├── src/
│   └── email_analyzer.py
├── tests/
│   └── test_email.py
├── data/
├── scripts/
│   ├── setup_env.py
│   ├── setup.sh
│   ├── setup.ps1
│   └── generate_demo_data.py
└── docs/
```

## System Requirements

| Mode | CPU | RAM | Disk | GPU |
|------|-----|-----|------|-----|
| Demo | Any | 1 GB | 500 MB | Not needed |

## Installation

### Recommended (all platforms) — automated bootstrap

Handles missing `ensurepip`, symlink restrictions, and installs dependencies into `.venv`:

```bash
git clone https://github.com/k-vandith/email-threat-forensics.git
cd email-threat-forensics
python3 scripts/setup_env.py    # or:  python scripts/setup_env.py
```

Then activate:

```bash
# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

### Manual setup

#### Windows (PowerShell)

```powershell
git clone https://github.com/k-vandith/email-threat-forensics.git
cd email-threat-forensics
python -m venv .venv --copies
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### Linux / macOS

```bash
git clone https://github.com/k-vandith/email-threat-forensics.git
cd email-threat-forensics
# If venv fails with ensurepip errors:
#   sudo apt install python3-venv python3-pip
python3 -m venv .venv --copies
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Why `--copies`?

Some environments cannot create symlinks inside a venv (`Operation not permitted` on `lib64 → lib`). Using `--copies` avoids that. `scripts/setup_env.py` tries `--copies` first automatically.

## Environment Variables

None required for demo mode.

## Dataset / Demo Mode

```bash
python scripts/generate_demo_data.py
```

Creates sample `.eml` fixtures under `data/`.

## Running the Application

```bash
streamlit run src/email_analyzer.py
```

## API Usage

```python
from src.email_analyzer import analyze_email
result = analyze_email(open("data/phishing_sample.eml", "rb").read())
print(result["risk_score"], result["signals"])
```

## Testing

```bash
pytest -v
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError: src` | Run from project root; ensure `PYTHONPATH=.` |
| `venv` / ensurepip fails | Run `python3 scripts/setup_env.py` or install `python3-venv` |
| `Operation not permitted` on lib64 | Use `python3 -m venv .venv --copies` |
| Missing dependency | Activate `.venv` and re-run `pip install -r requirements.txt` |

## Limitations

- Heuristic scoring; not a replacement for full secure-email gateways.
- Attachment content is metadata-only (no sandbox detonation).
- Live DNS lookups for SPF are optional and disabled in pure offline mode.

## Security / Privacy

- Defensive forensics only.
- Do not commit real production mailboxes to public repositories.

## Future Improvements

- YARA rules for attachment triage
- STIX/TAXII IOC export
- Multi-message campaign correlation

## License

MIT

## Interface

```bash
python run.py
```

Opens the local Streamlit workspace on port 8501. Demo paths work without GPU, webcam, or a paid API. `streamlit run src/app.py` is equivalent.
