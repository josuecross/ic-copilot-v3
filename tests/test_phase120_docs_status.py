from __future__ import annotations

from pathlib import Path


def test_docs_mention_phase129_product_only_surface() -> None:
    readme = Path("README.md").read_text()
    agents = Path("AGENTS.md").read_text()
    product_core = Path("docs/PRODUCT_CORE.md").read_text()
    assert "Phase 1.36C" in readme
    assert "Phase 1.36C" in agents
    assert "local_knowledge" in readme
    assert "local_knowledge" in agents
    assert "IncidentBrief" in product_core
    assert "AllowedTarget" in product_core
    assert "deterministic verifier" in product_core
