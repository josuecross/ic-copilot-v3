from __future__ import annotations

from pathlib import Path


def test_static_ui_contains_required_sections():
    html = Path("src/ic_copilot/web/templates/index.html").read_text()
    assert "<textarea" in html
    assert 'id="run-button"' in html
    assert "Product Runtime Status" in html
    assert "Pipeline Progress" in html
    assert "IC Whisper Output" in html
    assert "Debug / Trace" in html
    assert "Feedback" in html
    assert "Recent Runs" in html
    assert "Product Knowledge Status" in html
    assert "Personal Calibration Mode" not in html
    assert "Artifact Curation" not in html
