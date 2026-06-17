from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


CHECKS = [
    ("pytest", [sys.executable, "-m", "pytest", "-q"]),
    ("ruff", [sys.executable, "-m", "ruff", "check", "."]),
    ("fixture validation", [sys.executable, "scripts/validate_fixture_shapes.py"]),
    ("contract replay script", [sys.executable, "scripts/run_replay_eval.py"]),
    (
        "simplified product eval",
        [
            sys.executable,
            "scripts/run_simplified_product_eval.py",
            "--output-json",
            ".ic_copilot/product_eval/simplified_product_eval.json",
            "--output-md",
            ".ic_copilot/product_eval/simplified_product_eval.md",
        ],
    ),
    (
        "raw paste product eval",
        [
            sys.executable,
            "scripts/run_raw_paste_product_eval.py",
            "--output-json",
            ".ic_copilot/product_eval/raw_paste_product_eval.json",
            "--output-md",
            ".ic_copilot/product_eval/raw_paste_product_eval.md",
            "--audit-json",
            ".ic_copilot/knowledge_intake/reports/latest_full_product_audit.json",
            "--audit-md",
            ".ic_copilot/knowledge_intake/reports/latest_full_product_audit.md",
        ],
    ),
    (
        "GUI raw golden eval",
        [
            sys.executable,
            "scripts/run_gui_raw_golden_eval.py",
            "--output-json",
            ".ic_copilot/product_eval/gui_raw_golden_eval.json",
            "--output-md",
            ".ic_copilot/product_eval/gui_raw_golden_eval.md",
        ],
    ),
    (
        "product knowledge example validates",
        [sys.executable, "-m", "ic_copilot.cli", "validate-knowledge", "data/product_knowledge_example"],
    ),
    (
        "knowledge bundle intake review",
        [
            sys.executable,
            "scripts/review_knowledge_bundle.py",
            "data/sample/knowledge_bundle_intake/owner_aligned_bundle",
            "--knowledge-dir",
            "data/product_knowledge_example",
            "--require-review-approved",
        ],
    ),
    (
        "knowledge bundle intake apply dry-run",
        [
            sys.executable,
            "scripts/apply_approved_knowledge_bundle.py",
            "data/sample/knowledge_bundle_intake/owner_aligned_bundle",
            "--knowledge-dir",
            "data/product_knowledge_example",
            "--dry-run",
        ],
    ),
    (
        "extracted knowledge bundle batch review",
        [
            sys.executable,
            "scripts/review_extracted_knowledge_bundles.py",
            "data/sample/knowledge_bundle_intake",
            "--knowledge",
            "data/product_knowledge_example",
            "--require-review-approved",
            "--no-report",
        ],
    ),
    (
        "extracted knowledge bundle delta dry-run",
        [
            sys.executable,
            "scripts/apply_extracted_knowledge_delta.py",
            "data/sample/knowledge_bundle_intake",
            "--knowledge",
            "data/product_knowledge_example",
            "--registry",
            ".ic_copilot/knowledge_intake/gate_registry/applied_bundles.jsonl",
            "--dry-run",
            "--no-report",
        ],
    ),
    (
        "missing product knowledge fails closed",
        [
            sys.executable,
            "-c",
            "from ic_copilot.pipeline import run_pipeline; "
            "from ic_copilot.runtime_config import ProductRuntimeConfig; "
            "from ic_copilot.llm.fixture_client import FixtureLLMClient; "
            "from ic_copilot.product_knowledge import ProductKnowledgeError; "
            "cfg=ProductRuntimeConfig.model_validate({'product_knowledge_path': '.ic_copilot/missing_knowledge_gate'}); "
            "ok=False\n"
            "try:\n"
            "    run_pipeline('data/sample/incidents/revpro_early_engage.txt', save_trace=False, llm_client=FixtureLLMClient(), runtime_config=cfg)\n"
            "except ProductKnowledgeError as exc:\n"
            "    ok='Product knowledge folder is missing or invalid' in str(exc)\n"
            "assert ok",
        ],
    ),
    (
        "product knowledge runtime smoke",
        [
            sys.executable,
            "-c",
            "from ic_copilot.pipeline import run_pipeline; "
            "from ic_copilot.runtime_config import ProductRuntimeConfig; "
            "from ic_copilot.llm.fixture_client import FixtureLLMClient; "
            "cfg=ProductRuntimeConfig.model_validate({'product_knowledge_path': 'data/product_knowledge_example'}); "
            "r=run_pipeline('data/sample/incidents/revpro_early_engage.txt', save_trace=False, llm_client=FixtureLLMClient(), runtime_config=cfg); "
            "assert r['final_output'].startswith('SAY THIS:'); assert r['trace'].command_registry_size > 0",
        ],
    ),
    (
        "CLI help product surface",
        [
            sys.executable,
            "-c",
            "import subprocess, sys; "
            "out=subprocess.run([sys.executable,'-m','ic_copilot.cli','--help'],capture_output=True,text=True,check=True).stdout.lower(); "
            "assert 'validate-knowledge' in out and 'knowledge-status' in out; "
            "assert 'shadow' not in out and 'artifact' not in out and 'calibration' not in out and 'corpus' not in out",
        ],
    ),
    (
        "IncidentBrief, allowed target, and semantic stale regression",
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_phase132_incident_brief.py",
            "tests/test_phase127_clean_context_semantic_intent.py",
            "-q",
        ],
    ),
    (
        "web app product surface",
        [
            sys.executable,
            "-c",
            "from fastapi.testclient import TestClient; from ic_copilot.web.app import create_app; "
            "c=TestClient(create_app(db_path='.ic_copilot/web_gate_no_curation.sqlite3')); "
            "assert c.get('/health').json()['status']=='ok'\n"
            "for path in ['/api/artifacts/packages','/api/corrections/drafts','/api/personal-corpus/summary']:\n"
            "    assert c.get(path).status_code==404\n"
            "html=c.get('/').text; "
            "assert 'Artifact Curation' not in html and 'Developer path overrides' not in html and 'Mark run reviewed' not in html; "
            "assert 'ai-badge' in html and 'knowledge-badge' in html",
        ],
    ),
    (
        "latest-window bounded runtime and timeout resilience",
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_phase130_large_input_resilience.py",
            "-q",
        ],
    ),
    (
        "latency smoke script is available",
        [sys.executable, "scripts/run_product_latency_smoke.py", "--help"],
    ),
    (
        "role-aware targeting and turn reconstruction",
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_phase131_role_targeting.py",
            "-q",
        ],
    ),
    ("web safety audit", [sys.executable, "scripts/audit_web_console.py"]),
    (
        "personal regression eval",
        [
            sys.executable,
            "scripts/run_personal_regression_eval.py",
            "--output-json",
            ".ic_copilot/personal_regression/gate_results.json",
            "--output-md",
            ".ic_copilot/personal_regression/gate_results.md",
            "--fail-on-safety",
        ],
    ),
    (
        "repo audit strict",
        [
            sys.executable,
            "scripts/audit_repo_conflicts.py",
            "--output-json",
            ".ic_copilot/repo_audit/gate_repo_audit.json",
            "--output-md",
            ".ic_copilot/repo_audit/gate_repo_audit.md",
            "--strict",
        ],
    ),
]


def _tail(text: str, limit: int = 4000) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[-limit:]


def main() -> int:
    print("IC Copilot Phase 1.36C Acceptance Gate")
    print("Default gate is product-only and non-network.")
    print()
    passed = 0
    for label, command in CHECKS:
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        if completed.returncode == 0:
            print(f"[PASS] {label}")
            passed += 1
            continue

        print(f"[FAIL] {label}")
        print(f"command: {' '.join(command)}")
        print(f"exit code: {completed.returncode}")
        if completed.stdout.strip():
            print("stdout:")
            print(_tail(completed.stdout))
        if completed.stderr.strip():
            print("stderr:")
            print(_tail(completed.stderr))
        return completed.returncode or 1

    print()
    print(f"All {passed}/{len(CHECKS)} checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
