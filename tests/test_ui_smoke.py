from pathlib import Path

import src.app as app
from src.webapp import SignalTraceHandler, analyze_message


def test_ui_entrypoint():
    assert callable(app.main)


def test_local_workspace_handler_and_assets():
    assert callable(SignalTraceHandler.do_GET)
    root = Path(__file__).resolve().parents[1]
    assert (root / "web" / "index.html").is_file()
    assert (root / "web" / "styles.css").is_file()
    assert (root / "web" / "app.js").is_file()
    result = analyze_message("From: sender@example.test\nSubject: hello\n\nHi")
    assert result["filename"] == "message.eml"
