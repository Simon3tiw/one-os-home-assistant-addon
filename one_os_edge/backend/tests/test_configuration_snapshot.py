from __future__ import annotations

import json
from pathlib import Path

from one_os_addon.app import create_app
from one_os_addon.configuration_snapshot import (
    ConfigurationSnapshotRepository,
    ConfigurationSnapshotSync,
    ConfigurationSyncError,
    build_selected_projection,
    canonical_projection,
)
from one_os_addon.models import (
    Asset,
    ConfigurationSnapshot,
    EdgeIdentity,
    Point,
    Site,
    SourceBinding,
    Space,
    Structure,
)


def test_canonical_projection_matches_normative_golden_vector() -> None:
    contract = (
        Path(__file__).parents[3]
        / "docs/reference/contracts/configuration-snapshot/v1/canonical-vectors.json"
    )
    vector = json.loads(contract.read_bytes())

    canonical, digest = canonical_projection(vector["projection"])

    assert len(canonical) == vector["canonicalLength"]
    assert digest == vector["projectionSha256"]
    assert canonical == json.dumps(
        vector["projection"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _inventory(session) -> None:
    session.add(Site(id="site-1", installation_id="local", name="secret site"))
    for structure_id, name in (("structure-z", "Z building"), ("structure-a", "A building")):
        session.add(
            Structure(
                id=structure_id,
                site_id="site-1",
                parent_id=None,
                type="Building",
                name=name,
                source_key=f"floor:HA-{structure_id}",
            )
        )
    session.flush()
    session.add_all(
        [
            Space(
                id="space-z",
                structure_id="structure-z",
                type="MechanicalRoom",
                name="Plant",
                source_key="area:HA-area-z",
            ),
            Space(
                id="space-a",
                structure_id="structure-a",
                type="Room",
                name="Room",
                source_key="area:HA-area-a",
            ),
        ]
    )
    session.flush()
    session.add_all(
        [
            Asset(
                id="asset-z",
                space_id="space-z",
                type="HeatPump",
                name="Heat pump",
                source_key="device:HA-device-z",
            ),
            Asset(
                id="asset-a",
                space_id="space-a",
                type="Equipment",
                name="Excluded asset",
                source_key="device:HA-device-a",
            ),
        ]
    )
    session.flush()
    common = {
        "registry_id": "sensor.private_entity",
        "current_entity_id": "sensor.private_entity",
        "source_name": "Source temperature",
        "source_unit": "°C",
        "raw_value": "SECRET_RAW_STATE",
        "attributes_json": '{"secret":"RAW_ATTRIBUTE"}',
        "ontology_class": "https://brickschema.org/schema/Brick#Temperature_Sensor",
        "ontology_class_source": "one_os_override",
        "evidence_json": '{"domain":"sensor","deviceClass":"temperature"}',
        "selection_intent": "include",
        "review_status": "reviewed",
        "lifecycle": "active",
        "binding_stability": "stable",
    }
    session.add_all(
        [
            Point(
                id="point-z",
                asset_id="asset-z",
                source_key="entity:HA-registry-id",
                display_name="Supply temperature",
                display_unit="°F",
                decimals=1,
                **common,
            ),
            Point(
                id="point-unselected",
                asset_id="asset-a",
                source_key="entity:HA-unselected",
                selection_intent="exclude",
                **{key: value for key, value in common.items() if key != "selection_intent"},
            ),
            Point(
                id="point-ambiguous",
                asset_id="asset-a",
                source_key="entity:HA-ambiguous",
                binding_stability="ambiguous",
                **{key: value for key, value in common.items() if key != "binding_stability"},
            ),
        ]
    )
    session.flush()
    session.add_all(
        [
            SourceBinding(
                id="binding-z",
                registry_kind="entity",
                registry_id="HA-registry-id",
                object_id="point-z",
                active=True,
            ),
            SourceBinding(
                id="binding-unselected",
                registry_kind="entity",
                registry_id="HA-unselected",
                object_id="point-unselected",
                active=True,
            ),
            SourceBinding(
                id="binding-ambiguous",
                registry_kind="entity",
                registry_id="HA-ambiguous",
                object_id="point-ambiguous",
                active=True,
            ),
        ]
    )
    session.commit()


def test_projection_includes_only_effective_points_minimal_parents_and_effective_overrides(
    tmp_path: Path,
) -> None:
    app = create_app(database_url=f"sqlite:///{tmp_path / 'projection.db'}", pairing_backend=False)
    with app.state.session() as session:
        _inventory(session)
        projection = build_selected_projection(session)

    assert projection == {
        "structures": [{"id": "structure-z", "name": "Z building", "ontologyClass": "Building"}],
        "spaces": [
            {
                "id": "space-z",
                "structureId": "structure-z",
                "name": "Plant",
                "ontologyClass": "MechanicalRoom",
            }
        ],
        "assets": [
            {
                "id": "asset-z",
                "spaceId": "space-z",
                "name": "Heat pump",
                "ontologyClass": "HeatPump",
            }
        ],
        "points": [
            {
                "id": "point-z",
                "assetId": "asset-z",
                "name": "Supply temperature",
                "ontologyClass": "Temperature_Sensor",
                "valueType": "number",
                "canonicalUnit": "Cel",
                "displayUnit": "degF",
                "decimals": 1,
            }
        ],
    }
    outbound = canonical_projection(projection)[0]
    for forbidden in (
        b"sensor.private_entity",
        b"HA-registry-id",
        b"HA-device",
        b"HA-area",
        b"SECRET_RAW_STATE",
        b"RAW_ATTRIBUTE",
        b"point-unselected",
        b"point-ambiguous",
    ):
        assert forbidden not in outbound
    app.state.engine.dispose()


def test_projection_arrays_are_id_sorted_and_have_complete_parent_references(
    tmp_path: Path,
) -> None:
    app = create_app(database_url=f"sqlite:///{tmp_path / 'order.db'}", pairing_backend=False)
    with app.state.session() as session:
        _inventory(session)
        extra = Point(
            id="point-a",
            asset_id="asset-z",
            source_key="entity:second",
            registry_id="second",
            current_entity_id="sensor.second",
            source_name="Second",
            source_unit="°C",
            ontology_class="Temperature_Sensor",
            ontology_class_source="one_os_override",
            evidence_json='{"domain":"sensor","deviceClass":"temperature"}',
            selection_intent="include",
            review_status="reviewed",
            lifecycle="active",
            binding_stability="stable",
        )
        session.add(extra)
        session.flush()
        session.add(
            SourceBinding(
                id="binding-second",
                registry_kind="entity",
                registry_id="second",
                object_id="point-a",
                active=True,
            )
        )
        session.commit()
        projection = build_selected_projection(session)

    for key in projection:
        assert [item["id"] for item in projection[key]] == sorted(
            item["id"] for item in projection[key]
        )
    structure_ids = {item["id"] for item in projection["structures"]}
    space_ids = {item["id"] for item in projection["spaces"]}
    asset_ids = {item["id"] for item in projection["assets"]}
    assert all(item["structureId"] in structure_ids for item in projection["spaces"])
    assert all(item["spaceId"] in space_ids for item in projection["assets"])
    assert all(item["assetId"] in asset_ids for item in projection["points"])
    app.state.engine.dispose()


def _prepared_repository(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    app = create_app(database_url=f"sqlite:///{tmp_path / 'snapshots.db'}", pairing_backend=False)
    with app.state.session() as session:
        _inventory(session)
        identity = session.get(EdgeIdentity, 1)
        identity.status = "paired"
        session.commit()
        installation_id = identity.installation_id
    return app, ConfigurationSnapshotRepository(app.state.session), installation_id


def test_unchanged_projection_does_not_allocate_new_version_and_change_waits_for_ack(
    tmp_path: Path,
) -> None:
    app, repository, installation_id = _prepared_repository(tmp_path)

    first = repository.prepare(installation_id)
    same_pending = repository.prepare(installation_id)
    assert first is not None
    assert same_pending.payload == first.payload
    assert same_pending.snapshot_id == first.snapshot_id
    assert same_pending.config_version == 1

    with app.state.session() as session:
        session.get(Point, "point-z").display_name = "Changed while pending"
        session.commit()
    coalesced = repository.prepare(installation_id)
    assert coalesced.payload == first.payload

    repository.ack(first.snapshot_id)
    second = repository.prepare(installation_id)
    assert second is not None
    assert second.config_version == 2
    assert second.snapshot_id != first.snapshot_id
    assert b"Changed while pending" in second.payload
    repository.ack(second.snapshot_id)
    assert repository.prepare(installation_id) is None
    app.state.engine.dispose()


def test_pending_payload_hashes_and_attempt_metadata_survive_restart_exactly(
    tmp_path: Path,
) -> None:
    app, repository, installation_id = _prepared_repository(tmp_path)
    pending = repository.prepare(installation_id)
    assert pending is not None
    decoded = json.loads(pending.payload)
    assert decoded["snapshotId"] == pending.snapshot_id
    assert decoded["installationId"] == installation_id
    assert decoded["configVersion"] == 1
    assert decoded["projectionSha256"] == pending.projection_sha256
    assert set(decoded) == {
        "schemaVersion",
        "snapshotId",
        "installationId",
        "configVersion",
        "capturedAt",
        "projectionSha256",
        "structures",
        "spaces",
        "assets",
        "points",
    }

    repository.record_attempt(pending.snapshot_id)
    restarted = ConfigurationSnapshotRepository(app.state.session).pending()
    assert restarted is not None
    assert restarted.payload == pending.payload
    assert restarted.request_sha256 == pending.request_sha256
    assert restarted.attempt_count == 1
    assert restarted.last_attempt_at is not None
    with app.state.session() as session:
        row = session.get(ConfigurationSnapshot, pending.snapshot_id)
        assert row.created_at is not None
        assert row.acked_at is None
        assert "PRIVATE KEY" not in row.payload.decode("utf-8")
    app.state.engine.dispose()


class _IdentityMaterial:
    def read_identity_credential(self):
        return "CERTIFICATE", "CHAIN"

    def identity_private_pem(self):
        return "PRIVATE KEY"


class _SnapshotCentral:
    def __init__(self) -> None:
        self.uploads: list[bytes] = []
        self.status_calls = 0
        self.accepted: dict | None = None
        self.lose_response = False

    def upload_configuration_snapshot(self, payload, certificate, private_key):
        assert certificate == "CERTIFICATECHAIN"
        assert private_key == "PRIVATE KEY"
        self.uploads.append(payload)
        request = json.loads(payload)
        self.accepted = {
            "status": "accepted",
            "snapshotId": request["snapshotId"],
            "installationId": request["installationId"],
            "configVersion": request["configVersion"],
            "projectionSha256": request["projectionSha256"],
            "acceptedAt": "2026-08-07T12:00:00Z",
            "activePointCount": len(request["points"]),
        }
        if self.lose_response:
            self.lose_response = False
            raise OSError("response lost")
        return self.accepted

    def configuration_status(self, certificate, private_key):
        assert certificate == "CERTIFICATECHAIN"
        assert private_key == "PRIVATE KEY"
        self.status_calls += 1
        if self.accepted is None:
            return {"status": "none", "installationId": None}
        return {key: value for key, value in self.accepted.items() if key != "snapshotId"}


def _identity(installation_id: str, status="paired") -> dict:
    return {
        "installationId": installation_id,
        "status": status,
        "credentialId": "credential",
        "activeSpkiSha256": "x" * 43,
        "certificateSha256": "y" * 43,
        "certificateNotAfter": "2099-08-07T12:00:00+00:00",
    }


def test_response_loss_and_restart_reconcile_without_changing_or_reposting_bytes(
    tmp_path: Path,
) -> None:
    app, repository, installation_id = _prepared_repository(tmp_path)
    central = _SnapshotCentral()
    central.lose_response = True
    sync = ConfigurationSnapshotSync(
        repository, lambda: _identity(installation_id), _IdentityMaterial(), central
    )

    try:
        sync.run_once()
    except ConfigurationSyncError as error:
        assert str(error) == "configuration_upload_unreachable"
    else:
        raise AssertionError("response loss must remain pending")
    original = central.uploads[0]

    restarted = ConfigurationSnapshotSync(
        ConfigurationSnapshotRepository(app.state.session),
        lambda: _identity(installation_id),
        _IdentityMaterial(),
        central,
    )
    assert restarted.run_once() == "acked"
    assert central.status_calls == 1
    assert central.uploads == [original]
    assert ConfigurationSnapshotRepository(app.state.session).pending() is None
    app.state.engine.dispose()


def test_exact_retry_happens_only_after_separate_status_budget(tmp_path: Path) -> None:
    app, repository, installation_id = _prepared_repository(tmp_path)
    central = _SnapshotCentral()
    central.lose_response = True
    sync = ConfigurationSnapshotSync(
        repository, lambda: _identity(installation_id), _IdentityMaterial(), central
    )
    try:
        sync.run_once()
    except ConfigurationSyncError:
        pass
    central.accepted = None

    assert sync.run_once() == "retry_pending"
    assert central.status_calls == 1
    assert len(central.uploads) == 1
    assert sync.run_once() == "acked"
    assert central.uploads[0] == central.uploads[1]
    app.state.engine.dispose()


def test_projection_changed_during_upload_becomes_next_monotone_snapshot(tmp_path: Path) -> None:
    app, repository, installation_id = _prepared_repository(tmp_path)
    central = _SnapshotCentral()
    original_upload = central.upload_configuration_snapshot

    def upload_and_change(payload, certificate, private_key):
        response = original_upload(payload, certificate, private_key)
        with app.state.session() as session:
            session.get(Point, "point-z").display_name = "Changed during upload"
            session.commit()
        return response

    central.upload_configuration_snapshot = upload_and_change
    sync = ConfigurationSnapshotSync(
        repository, lambda: _identity(installation_id), _IdentityMaterial(), central
    )

    assert sync.run_once() == "acked"
    central.upload_configuration_snapshot = original_upload
    assert sync.run_once() == "acked"

    first, second = map(json.loads, central.uploads)
    assert first["configVersion"] == 1
    assert second["configVersion"] == 2
    assert first["snapshotId"] != second["snapshotId"]
    assert b"Changed during upload" not in central.uploads[0]
    assert b"Changed during upload" in central.uploads[1]
    app.state.engine.dispose()


def test_database_or_identity_store_failure_is_fail_closed_before_network(tmp_path: Path) -> None:
    app, repository, installation_id = _prepared_repository(tmp_path)
    central = _SnapshotCentral()

    class BrokenRepository(ConfigurationSnapshotRepository):
        def pending(self):
            raise OSError("database unavailable")

    sync = ConfigurationSnapshotSync(
        BrokenRepository(app.state.session),
        lambda: _identity(installation_id),
        _IdentityMaterial(),
        central,
    )
    try:
        sync.run_once()
    except OSError:
        pass
    else:
        raise AssertionError("database failure must fail closed")
    assert central.uploads == [] and central.status_calls == 0

    class BrokenMaterial(_IdentityMaterial):
        def read_identity_credential(self):
            raise OSError("identity unavailable")

    sync = ConfigurationSnapshotSync(
        repository, lambda: _identity(installation_id), BrokenMaterial(), central
    )
    assert sync.run_once() == "ineligible"
    assert central.uploads == [] and central.status_calls == 0
    app.state.engine.dispose()


def test_unpaired_revoked_missing_or_expired_identity_never_uses_network(tmp_path: Path) -> None:
    for index, identity in enumerate(
        (
            _identity("unused", "unpaired"),
            _identity("unused", "revoked"),
            _identity("unused", "identity_missing_after_restore"),
            _identity("unused") | {"certificateNotAfter": "2020-01-01T00:00:00Z"},
            _identity("unused") | {"credentialId": None},
        )
    ):
        app, repository, installation_id = _prepared_repository(tmp_path / str(index))
        identity["installationId"] = installation_id
        central = _SnapshotCentral()
        sync = ConfigurationSnapshotSync(
            repository, lambda value=identity: value, _IdentityMaterial(), central
        )
        assert sync.run_once() == "ineligible"
        assert central.uploads == [] and central.status_calls == 0
        app.state.engine.dispose()
