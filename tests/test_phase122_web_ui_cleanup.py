from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from ic_copilot.web.app import create_app


def test_main_ui_is_ic_first_and_curation_collapsed(tmp_path) -> None:
    html = TestClient(create_app(db_path=tmp_path / "web.sqlite3")).get("/").text
    assert "Product Runtime Status" in html
    assert "Product Knowledge Status" in html
    assert "Paste Slack Incident" in html
    assert "IC Whisper Output" in html
    assert "Suggestion only · manual copy only · not executed." in html
    assert "Artifact Curation" not in html
    assert "Promotion Buttons" not in html
    assert "Personal Calibration Mode" not in html


def test_static_js_has_safe_object_formatter() -> None:
    text = Path("src/ic_copilot/web/static/app.js").read_text()
    assert "function formatValue" in text
    assert "blocker_type" in text
    assert "[object Object]" not in text


def test_default_web_app_has_no_curation_routes(tmp_path) -> None:
    client = TestClient(create_app(db_path=tmp_path / "web.sqlite3"))
    assert client.get("/api/artifacts/reviewed").status_code == 404
    assert client.get("/api/corrections/drafts").status_code == 404
