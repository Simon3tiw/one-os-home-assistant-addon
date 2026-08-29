import json
import os
import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path

import yaml
from one_os_addon.app import create_app
from one_os_addon.version import RELEASE_VERSION

ADDON_CONFIG = Path(__file__).resolve().parents[2] / "config.yaml"
CI_WORKFLOW = Path(__file__).resolve().parents[3] / ".github/workflows/ci.yml"
REPOSITORY_ROOT = ADDON_CONFIG.parents[1]
BUILD_RELEASE_BUNDLE = REPOSITORY_ROOT / "scripts" / "build-release-bundle.sh"


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


def test_release_version_is_consistent_across_runtime_and_package_metadata(tmp_path: Path) -> None:
    manifest = yaml.safe_load(ADDON_CONFIG.read_text(encoding="utf-8"))
    project = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    frontend = json.loads(
        (ADDON_CONFIG.parent / "frontend" / "package.json").read_text(encoding="utf-8")
    )

    assert manifest["version"] == RELEASE_VERSION
    assert project["project"]["version"] == RELEASE_VERSION
    assert frontend["version"] == RELEASE_VERSION
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'version.db'}",
        pairing_backend=False,
        start_pairing_worker=False,
    )
    assert app.version == RELEASE_VERSION
    app.state.engine.dispose()


def test_release_bundle_is_byte_reproducible_and_metadata_normalized(tmp_path: Path) -> None:
    archives = []
    for name in ("first", "second"):
        output = tmp_path / name
        subprocess.run(  # noqa: S603 - fixed repository-owned release script
            [BUILD_RELEASE_BUNDLE, output], check=True, capture_output=True, text=True
        )
        archives.append(output / "one-os-edge-addon-bundle.tar.gz")

    assert archives[0].read_bytes() == archives[1].read_bytes()
    with tarfile.open(archives[0], "r:gz") as bundle:
        members = bundle.getmembers()
    assert members
    assert {member.mtime for member in members} == {0}
    assert {member.uid for member in members} == {0}
    assert {member.gid for member in members} == {0}
    assert {member.uname for member in members} == {""}
    assert {member.gname for member in members} == {""}
    assert {member.mode for member in members if member.isdir()} == {0o755}
    assert {member.mode for member in members if member.isfile()} <= {0o644, 0o755}


def test_release_bundle_is_independent_of_all_source_modes(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    perturbed_repository = tmp_path / "perturbed-repository"
    perturbed_output = tmp_path / "perturbed"
    subprocess.run(  # noqa: S603 - fixed repository-owned release script
        [BUILD_RELEASE_BUNDLE, baseline], check=True, capture_output=True, text=True
    )
    shutil.copytree(
        REPOSITORY_ROOT / "one_os_edge",
        perturbed_repository / "one_os_edge",
        ignore=shutil.ignore_patterns(
            "node_modules", "dist", "test-results", ".venv", "__pycache__", "*.pyc"
        ),
    )
    shutil.copy2(REPOSITORY_ROOT / "README.md", perturbed_repository / "README.md")
    shutil.copytree(REPOSITORY_ROOT / "scripts", perturbed_repository / "scripts")
    for path in perturbed_repository.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)
    subprocess.run(  # noqa: S603 - copied repository-owned release script
        [
            "/usr/bin/bash",
            perturbed_repository / "scripts/build-release-bundle.sh",
            perturbed_output,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert (baseline / "one-os-edge-addon-bundle.tar.gz").read_bytes() == (
        perturbed_output / "one-os-edge-addon-bundle.tar.gz"
    ).read_bytes()


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


def test_release_bundle_requires_non_vacuous_postgresql_gate() -> None:
    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    gate = workflow["jobs"]["postgresql-migrations"]
    assert "postgres" in gate["services"]
    environment = gate["env"]
    assert environment["ONE_OS_EDGE_TEST_POSTGRES_ADMIN_URL"].startswith("postgresql+psycopg://")
    assert environment["ONE_OS_EDGE_TEST_POSTGRES_URL"].startswith("postgresql+psycopg://")
    commands = "\n".join(step.get("run", "") for step in gate["steps"] if isinstance(step, dict))
    assert "PGPASSWORD=postgres psql" in commands
    assert "postgres:***" not in commands
    assert "test_alembic_postgresql_compatibility.py" in commands
    assert "test_telemetry_authority_postgresql.py" in commands
    assert "postgresql-migrations" in workflow["jobs"]["release-bundle"]["needs"]


def test_install_verification_requires_current_database_head() -> None:
    install = (REPOSITORY_ROOT / "INSTALL.md").read_text(encoding="utf-8")
    assert '"databaseRevision": "0021"' in install
    assert '"databaseRevision": "0002"' not in install
    assert "Stop de bestaande ONE.OS Edge Connector-add-on" in install
    assert "private identity cross-store" in install
    assert "brondatabase ongewijzigd" in install
