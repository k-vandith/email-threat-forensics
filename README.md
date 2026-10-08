# Email Threat Detection & Forensic Intelligence Platform

Defensive local email forensics: phishing signals, SPF/DKIM/DMARC interpretation, IOC extraction, threat scoring.

## Installation

### Linux / macOS
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Windows PowerShell
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Demo
```bash
python scripts/generate_demo_data.py
python -c "from src.email_analyzer import analyze_eml_file; print(analyze_eml_file('data/sample/phishing_sample.eml'))"
pytest -v
```

## License
MIT
