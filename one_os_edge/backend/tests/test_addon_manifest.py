import json
import tomllib
from pathlib import Path

import yaml
from one_os_addon.version import RELEASE_VERSION

ADDON_CONFIG = Path(__file__).resolve().parents[2] / "config.yaml"
CI_WORKFLOW = Path(__file__).resolve().parents[3] / ".github/workflows/ci.yml"
REPOSITORY_ROOT = ADDON_CONFIG.parents[1]


def test_addon_backup_excludes_private_edge_identity() -> None:
    manifest = yaml.safe_load(ADDON_CONFIG.read_text(encoding="utf-8"))

    assert "panel_admin" not in manifest  # Home Assistant defaults this to true.
    assert manifest["homeassistant_api"] is True
    assert "hassio_api" not in manifest
    assert manifest["backup_exclude"] == [
        "identity",
        "identity/**",
        "telemetry-outbox",
        "telemetry-outbox/**",
    ]


def test_release_version_is_consistent_across_runtime_and_package_metadata() -> None:
    manifest = yaml.safe_load(ADDON_CONFIG.read_text(encoding="utf-8"))
    project = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    frontend = json.loads(
        (ADDON_CONFIG.parent / "frontend" / "package.json").read_text(encoding="utf-8")
    )

    assert manifest["version"] == RELEASE_VERSION
    assert project["project"]["version"] == RELEASE_VERSION
    assert frontend["version"] == RELEASE_VERSION


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
