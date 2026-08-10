from pathlib import Path

import yaml

ADDON_CONFIG = Path(__file__).resolve().parents[2] / "config.yaml"
CI_WORKFLOW = Path(__file__).resolve().parents[3] / ".github/workflows/ci.yml"


def test_addon_backup_excludes_private_edge_identity() -> None:
    manifest = yaml.safe_load(ADDON_CONFIG.read_text(encoding="utf-8"))

    assert manifest["panel_admin"] is True
    assert manifest["homeassistant_api"] is True
    assert "hassio_api" not in manifest
    assert manifest["backup_exclude"] == ["identity", "identity/**"]


def test_production_lock_is_hash_pinned_and_does_not_require_local_project_source() -> None:
    addon_root = ADDON_CONFIG.parent
    lock = (addon_root / "requirements.lock").read_text(encoding="utf-8")
    dockerfile = (addon_root / "Dockerfile").read_text(encoding="utf-8")

    assert "-e ." not in lock.splitlines()
    assert "--hash=sha256:" in lock
    assert (
        "COPY requirements.lock ./\nRUN pip install --no-cache-dir -r requirements.lock"
        in dockerfile
    )


def test_release_bundle_requires_real_phase2b_lifecycle_gate() -> None:
    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))

    gate = workflow["jobs"]["phase2b-lifecycle"]
    commands = "\n".join(step.get("run", "") for step in gate["steps"] if isinstance(step, dict))
    assert "test_phase2b_lifecycle_e2e.py" in commands
    assert "phase2b-lifecycle" in workflow["jobs"]["release-bundle"]["needs"]
