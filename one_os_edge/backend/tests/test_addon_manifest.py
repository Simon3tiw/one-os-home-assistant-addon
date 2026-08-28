import json
import os
import subprocess
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
    assert manifest["options"] == {
        "telemetry_enabled": False,
        "telemetry_authority_enabled": False,
        "soak_probe_enabled": False,
    }
    assert manifest["schema"] == {
        "telemetry_enabled": "bool",
        "telemetry_authority_enabled": "bool",
        "soak_probe_enabled": "bool",
    }
    assert manifest["backup_exclude"] == [
        "identity",
        "identity/**",
        "telemetry-outbox",
        "telemetry-outbox/**",
        "soak-probe",
        "soak-probe/**",
    ]


def test_manifest_has_separate_default_off_soak_probe_port() -> None:
    manifest = yaml.safe_load(ADDON_CONFIG.read_text(encoding="utf-8"))
    assert manifest["options"]["soak_probe_enabled"] is False
    assert manifest["schema"]["soak_probe_enabled"] == "bool"
    assert manifest["ports"]["9443/tcp"] is None
    assert "9443/tcp" in manifest["ports_description"]


def test_addon_runtime_reads_the_validated_telemetry_option() -> None:
    run_script = (
        ADDON_CONFIG.parent / "rootfs" / "etc" / "services.d" / "one-os" / "run"
    ).read_text(encoding="utf-8")

    assignment = (
        'ONE_OS_TELEMETRY_ENABLED="$(python3 -m one_os_addon.addon_options /data/options.json)"'
    )
    assert assignment in run_script
    assert "export ONE_OS_TELEMETRY_ENABLED" in run_script
    assert run_script.index(assignment) < run_script.index("exec uvicorn")


def test_addon_runtime_does_not_start_after_options_parser_failure(tmp_path: Path) -> None:
    run_script = (
        ADDON_CONFIG.parent / "rootfs" / "etc" / "services.d" / "one-os" / "run"
    ).read_text(encoding="utf-8")
    assignment = next(
        line for line in run_script.splitlines() if line.startswith('ONE_OS_TELEMETRY_ENABLED="$(')
    )
    marker = tmp_path / "uvicorn-started"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_python = fake_bin / "python3"
    fake_python.write_text("#!/bin/sh\nexit 78\n", encoding="utf-8")
    fake_python.chmod(0o700)

    completed = subprocess.run(  # noqa: S603 - fixed shell exercises startup semantics
        [
            "/bin/sh",
            "-c",
            "\n".join(
                (
                    "set -eu",
                    assignment,
                    "export ONE_OS_TELEMETRY_ENABLED",
                    f": > {marker}",
                )
            ),
        ],
        check=False,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 78
    assert not marker.exists()


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
