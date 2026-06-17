from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from scripts.bootstrap_product_knowledge import apply_bootstrap, build_bootstrap_plan


def _args(tmp_path: Path, **overrides):
    values = {
        "output": str(tmp_path / "local_knowledge"),
        "source_contract": "data/contract",
        "source_personal_regression": str(tmp_path / "personal_regression"),
        "source_corpus": str(tmp_path / "personal_corpus"),
        "source_product_readiness": str(tmp_path / "product_readiness"),
        "reviewed_by": "reviewer",
        "review_method": "external review",
        "reviewed_at": "2026-05-25",
        "assume_externally_reviewed": False,
        "dry_run": True,
        "apply": False,
        "force": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _write_candidates(tmp_path: Path) -> None:
    personal_regression = tmp_path / "personal_regression"
    personal_regression.mkdir()
    (personal_regression / "catalog_candidates.review_required.yaml").write_text(
        yaml.safe_dump(
            {
                "services": [
                    {
                        "service_id": "safe_service",
                        "canonical_name": "Safe Service",
                        "review_status": "review_required",
                    }
                ]
            }
        )
    )
    (personal_regression / "command_candidates.review_required.yaml").write_text(
        yaml.safe_dump(
            {
                "commands": [
                    {
                        "command_text_template": "@zsrebot oncall Safe Service",
                        "command_type": "oncall_lookup",
                        "requires_human_approval": True,
                        "read_only": True,
                        "safe_for_suggestion": True,
                    },
                    {
                        "command_text_template": "kubectl delete pod bad",
                        "command_type": "mutation",
                        "requires_human_approval": True,
                        "read_only": False,
                        "safe_for_suggestion": False,
                    },
                ]
            }
        )
    )
    generated = tmp_path / "personal_corpus/generated_views"
    generated.mkdir(parents=True)
    (generated / "personal_decision_moments.review_required.jsonl").write_text("")


def test_bootstrap_dry_run_writes_no_output(tmp_path) -> None:
    args = _args(tmp_path)
    plan = build_bootstrap_plan(args)
    assert plan["catalog_candidates_seen"] == 0
    assert not Path(args.output).exists()


def test_bootstrap_apply_creates_valid_contract_baseline(tmp_path) -> None:
    args = _args(tmp_path, apply=True, dry_run=False)
    plan = build_bootstrap_plan(args)
    validation = apply_bootstrap(args, plan)
    assert validation["passed"] is True
    assert (Path(args.output) / "manifest.yaml").exists()
    assert (Path(args.output) / "import_report/migration_report.json").exists()


def test_review_required_candidates_skipped_by_default(tmp_path) -> None:
    _write_candidates(tmp_path)
    args = _args(tmp_path)
    plan = build_bootstrap_plan(args)
    assert plan["catalog_candidates_seen"] == 1
    assert not plan["imported_catalog_candidates"]
    assert plan["rejected_catalog_candidates"]


def test_assume_external_review_imports_safe_and_rejects_unsafe(tmp_path) -> None:
    _write_candidates(tmp_path)
    args = _args(tmp_path, assume_externally_reviewed=True, apply=True, dry_run=False)
    plan = build_bootstrap_plan(args)
    assert len(plan["imported_catalog_candidates"]) == 1
    assert len(plan["imported_command_candidates"]) == 1
    assert len(plan["rejected_command_candidates"]) == 1
    validation = apply_bootstrap(args, plan)
    assert validation["passed"] is True
    report = json.loads((Path(args.output) / "import_report/migration_report.json").read_text())
    assert report["plan"]["rejected_command_candidates"]
