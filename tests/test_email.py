from pathlib import Path
from src.email_analyzer import analyze_eml_file

def test_phishing_sample():
    p = Path(__file__).resolve().parents[1] / "data" / "sample" / "phishing_sample.eml"
    if not p.exists():
        import runpy
        runpy.run_path(str(p.parents[2] / "scripts" / "generate_demo_data.py"))
    a = analyze_eml_file(p)
    assert a.threat_score > 0.3
    assert a.spf == "fail"
    assert any("bit.ly" in u for u in a.urls)
