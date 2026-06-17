from pathlib import Path

from ic_copilot.product_core import classify_module_path, product_core_report


def test_product_core_classifies_product_modules() -> None:
    assert classify_module_path(Path("src/ic_copilot/pipeline.py")) == "product"
    assert classify_module_path(Path("src/ic_copilot/web/app.py")) == "product"
    assert classify_module_path(Path("src/ic_copilot/runtime_resources.py")) == "product"


def test_product_core_classifies_offline_and_dev_surfaces() -> None:
    assert classify_module_path(Path("src/ic_copilot/artifacts/validation.py")) == "offline_curation"
    assert classify_module_path(Path("src/ic_copilot/previous_incident_calibration.py")) == "offline_curation"
    assert classify_module_path(Path("src/ic_copilot/shadow.py")) == "dev_eval"
    assert classify_module_path(Path("src/ic_copilot/llm/fixture_client.py")) == "dev_eval"
    assert classify_module_path(Path("tests/test_anything.py")) == "test"


def test_product_core_report_counts_paths() -> None:
    report = product_core_report(
        [
            Path("src/ic_copilot/pipeline.py"),
            Path("src/ic_copilot/artifacts/validation.py"),
            Path("tests/test_anything.py"),
        ]
    )
    assert report["counts"]["product"] == 1
    assert report["counts"]["offline_curation"] == 1
    assert report["counts"]["test"] == 1
