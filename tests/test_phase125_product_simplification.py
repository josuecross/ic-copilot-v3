from __future__ import annotations

from fastapi.testclient import TestClient

from ic_copilot.web.app import create_app


def test_default_web_app_has_no_curation_routes(tmp_path) -> None:
    client = TestClient(create_app(db_path=tmp_path / "web.sqlite3", input_dir=tmp_path / "inputs"))
    forbidden = (
        "/api/artifacts/packages",
        "/api/corrections/drafts",
        "/api/runs/example/mark-reviewed",
        "/api/runs/example/export-regression-draft",
    )
    for path in forbidden:
        assert client.get(path).status_code == 404


def test_default_web_app_exposes_product_knowledge_status(tmp_path) -> None:
    client = TestClient(create_app(db_path=tmp_path / "web.sqlite3", input_dir=tmp_path / "inputs"))
    config = client.get("/api/config").json()
    assert "product_knowledge" in config
    assert config["product_knowledge"]["path"] == "local_knowledge"
    assert client.get("/api/knowledge/status").status_code == 200
