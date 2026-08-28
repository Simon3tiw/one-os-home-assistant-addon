from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select

from .models import Asset, Audit, ConfigurationSnapshot, Point, SourceBinding, Space, Structure, uid

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}", re.ASCII)
_CLASS = re.compile(r"[A-Za-z][A-Za-z0-9._:-]{0,119}", re.ASCII)
_UNIT_MAP = {
    "°C": ("Cel", "degC"),
    "°F": ("Cel", "degF"),
    "%": ("%", "%"),
    "W": ("W", "W"),
    "kW": ("kW", "kW"),
    "Wh": ("W.h", "Wh"),
    "kWh": ("kW.h", "kWh"),
    "V": ("V", "V"),
    "A": ("A", "A"),
    "Hz": ("Hz", "Hz"),
    "Pa": ("Pa", "Pa"),
    "hPa": ("hPa", "hPa"),
    "ppm": ("[ppm]", "ppm"),
    "lx": ("lx", "lx"),
}
_DISPLAY_UNITS = {display: canonical for canonical, display in _UNIT_MAP.values()}
_DISPLAY_UNITS.update({source: canonical for source, (canonical, _display) in _UNIT_MAP.items()})


class SnapshotProjectionError(RuntimeError):
    pass


class ConfigurationSyncError(RuntimeError):
    pass


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def canonical_projection(projection: dict[str, Any]) -> tuple[bytes, str]:
    ordered = {
        key: sorted(projection[key], key=lambda item: item["id"])
        for key in ("structures", "spaces", "assets", "points")
    }
    payload = json.dumps(ordered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return payload, _b64u(hashlib.sha256(payload).digest())


def _valid_id(value: str) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _valid_name(value: str) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 160
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _ontology(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.rsplit("#", 1)[-1].rsplit("/", 1)[-1]
    return candidate if _CLASS.fullmatch(candidate) else None


def _value_type(evidence: dict[str, Any], source_unit: str | None) -> str:
    domain = evidence.get("domain")
    if domain in {"binary_sensor", "switch", "input_boolean"}:
        return "boolean"
    if domain in {"select", "input_select"} or evidence.get("options"):
        return "enum"
    if source_unit is not None or evidence.get("deviceClass") in {
        "temperature",
        "humidity",
        "carbon_dioxide",
        "power",
        "energy",
        "illuminance",
        "pressure",
        "atmospheric_pressure",
        "voltage",
        "current",
        "frequency",
    }:
        return "number"
    return "string"


def _units(point: Point, value_type: str) -> tuple[str | None, str | None] | None:
    if value_type != "number":
        return (None, None) if point.display_unit is None else None
    if point.source_unit is None:
        return (None, None) if point.display_unit is None else None
    normalized = _UNIT_MAP.get(point.source_unit)
    if normalized is None:
        return None
    canonical, default_display = normalized
    if point.display_unit is None:
        return canonical, default_display
    if _DISPLAY_UNITS.get(point.display_unit) != canonical:
        return None
    display = _UNIT_MAP.get(point.display_unit, (None, point.display_unit))[1]
    return canonical, display


def _point_node(point: Point) -> dict[str, Any] | None:
    if not _valid_id(point.id) or not _valid_id(point.asset_id):
        return None
    name = point.display_name or point.source_name
    ontology = _ontology(point.ontology_class)
    if not _valid_name(name) or ontology is None:
        return None
    try:
        evidence = json.loads(point.evidence_json)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(evidence, dict):
        return None
    value_type = _value_type(evidence, point.source_unit)
    units = _units(point, value_type)
    if units is None or (point.decimals is not None and not 0 <= point.decimals <= 9):
        return None
    canonical_unit, display_unit = units
    return {
        "id": point.id,
        "assetId": point.asset_id,
        "name": name,
        "ontologyClass": ontology,
        "valueType": value_type,
        "canonicalUnit": canonical_unit,
        "displayUnit": display_unit,
        "decimals": point.decimals if value_type == "number" else None,
    }


def build_selected_projection(session) -> dict[str, list[dict[str, Any]]]:
    """Project the effective selected set from one caller-owned read transaction."""
    candidates = session.scalars(
        select(Point).where(
            Point.selection_intent == "include",
            Point.review_status == "reviewed",
            Point.lifecycle == "active",
            Point.placement_conflict.is_(False),
        )
    ).all()
    structures: dict[str, dict[str, Any]] = {}
    spaces: dict[str, dict[str, Any]] = {}
    assets: dict[str, dict[str, Any]] = {}
    points: dict[str, dict[str, Any]] = {}
    for point in candidates:
        if point.binding_stability == "temporary" and not point.temporary_accepted:
            continue
        if point.binding_stability not in {"stable", "temporary"}:
            continue
        bindings = session.scalars(
            select(SourceBinding).where(
                SourceBinding.object_id == point.id,
                SourceBinding.registry_kind == "entity",
                SourceBinding.active.is_(True),
            )
        ).all()
        if len(bindings) != 1:
            continue
        asset = session.get(Asset, point.asset_id)
        space = session.get(Space, asset.space_id) if asset else None
        structure = session.get(Structure, space.structure_id) if space else None
        if (
            asset is None
            or space is None
            or structure is None
            or any(node.lifecycle != "active" for node in (asset, space, structure))
            or asset.placement_conflict
        ):
            continue
        point_node = _point_node(point)
        structure_class = _ontology(structure.type)
        space_class = _ontology(space.type)
        asset_class = _ontology(asset.type)
        if (
            point_node is None
            or not all(
                _valid_id(node.id) and _valid_name(node.name) for node in (structure, space, asset)
            )
            or structure_class is None
            or space_class is None
            or asset_class is None
        ):
            continue
        structures[structure.id] = {
            "id": structure.id,
            "name": structure.name,
            "ontologyClass": structure_class,
        }
        spaces[space.id] = {
            "id": space.id,
            "structureId": structure.id,
            "name": space.name,
            "ontologyClass": space_class,
        }
        assets[asset.id] = {
            "id": asset.id,
            "spaceId": space.id,
            "name": asset.name,
            "ontologyClass": asset_class,
        }
        points[point.id] = point_node
    result = {
        "structures": sorted(structures.values(), key=lambda item: item["id"]),
        "spaces": sorted(spaces.values(), key=lambda item: item["id"]),
        "assets": sorted(assets.values(), key=lambda item: item["id"]),
        "points": sorted(points.values(), key=lambda item: item["id"]),
    }
    limits = {"structures": 256, "spaces": 2048, "assets": 4096, "points": 20000}
    if any(len(result[key]) > limit for key, limit in limits.items()):
        raise SnapshotProjectionError("projection_limit_exceeded")
    return result


class ConfigurationSnapshotRepository:
    """Crash-safe, single-pending configuration snapshot repository."""

    def __init__(self, session_factory, clock=lambda: datetime.now(UTC)) -> None:
        self._session_factory = session_factory
        self._clock = clock
        self._lock = RLock()

    @staticmethod
    def _audit(session, row: ConfigurationSnapshot, action: str, detail: dict[str, Any]) -> None:
        session.add(
            Audit(
                id=uid("audit"),
                actor_id="system:edge-worker",
                action=action,
                object_id=row.snapshot_id,
                revision=row.attempt_count if action.endswith("attempt") else row.config_version,
                fields_json=json.dumps(detail, sort_keys=True, separators=(",", ":")),
            )
        )

    def pending(self) -> ConfigurationSnapshot | None:
        with self._lock, self._session_factory() as session:
            return session.scalar(
                select(ConfigurationSnapshot)
                .where(ConfigurationSnapshot.status == "pending")
                .order_by(ConfigurationSnapshot.config_version)
            )

    def prepare(self, installation_id: str) -> ConfigurationSnapshot | None:
        with self._lock, self._session_factory() as session:
            pending = session.scalar(
                select(ConfigurationSnapshot)
                .where(
                    ConfigurationSnapshot.installation_id == installation_id,
                    ConfigurationSnapshot.status == "pending",
                )
                .with_for_update()
            )
            if pending is not None:
                return pending
            projection = build_selected_projection(session)
            _projection_bytes, projection_sha256 = canonical_projection(projection)
            latest = session.scalar(
                select(ConfigurationSnapshot)
                .where(
                    ConfigurationSnapshot.installation_id == installation_id,
                    ConfigurationSnapshot.status == "acked",
                )
                .order_by(ConfigurationSnapshot.config_version.desc())
                .limit(1)
                .with_for_update()
            )
            if latest is not None and latest.projection_sha256 == projection_sha256:
                return None
            last_version = session.scalar(
                select(func.max(ConfigurationSnapshot.config_version)).where(
                    ConfigurationSnapshot.installation_id == installation_id
                )
            )
            config_version = (last_version or 0) + 1
            if config_version > 18446744073709551615:
                raise SnapshotProjectionError("config_version_exhausted")
            captured = self._clock().astimezone(UTC)
            body = {
                "schemaVersion": "1.0",
                "snapshotId": str(uuid4()),
                "installationId": installation_id,
                "configVersion": config_version,
                "capturedAt": captured.isoformat().replace("+00:00", "Z"),
                "projectionSha256": projection_sha256,
                **projection,
            }
            payload = json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            if len(payload) > 2 * 1024 * 1024:
                raise SnapshotProjectionError("snapshot_too_large")
            row = ConfigurationSnapshot(
                snapshot_id=body["snapshotId"],
                installation_id=installation_id,
                config_version=config_version,
                projection_sha256=projection_sha256,
                request_sha256=_b64u(hashlib.sha256(payload).digest()),
                payload=payload,
                status="pending",
                created_at=captured,
                attempt_count=0,
                needs_status_check=False,
            )
            session.add(row)
            self._audit(
                session,
                row,
                "configuration_snapshot.prepare",
                {"configVersion": config_version, "status": "pending"},
            )
            session.commit()
            return row

    def record_attempt(self, snapshot_id: str) -> ConfigurationSnapshot:
        with self._lock, self._session_factory() as session:
            row = session.scalar(
                select(ConfigurationSnapshot)
                .where(
                    ConfigurationSnapshot.snapshot_id == snapshot_id,
                    ConfigurationSnapshot.status == "pending",
                )
                .with_for_update()
            )
            if row is None:
                raise SnapshotProjectionError("pending_snapshot_missing")
            row.attempt_count += 1
            row.last_attempt_at = self._clock().astimezone(UTC)
            row.needs_status_check = True
            self._audit(
                session,
                row,
                "configuration_snapshot.attempt",
                {"attemptCount": row.attempt_count, "status": "pending"},
            )
            session.commit()
            return row

    def record_status_checked(self, snapshot_id: str) -> ConfigurationSnapshot:
        with self._lock, self._session_factory() as session:
            row = session.scalar(
                select(ConfigurationSnapshot)
                .where(
                    ConfigurationSnapshot.snapshot_id == snapshot_id,
                    ConfigurationSnapshot.status == "pending",
                )
                .with_for_update()
            )
            if row is None:
                raise SnapshotProjectionError("pending_snapshot_missing")
            if not row.needs_status_check:
                return row
            row.needs_status_check = False
            self._audit(
                session,
                row,
                "configuration_snapshot.status_checked",
                {"attemptCount": row.attempt_count, "status": "pending"},
            )
            session.commit()
            return row

    def ack(self, snapshot_id: str) -> ConfigurationSnapshot:
        with self._lock, self._session_factory() as session:
            row = session.scalar(
                select(ConfigurationSnapshot)
                .where(ConfigurationSnapshot.snapshot_id == snapshot_id)
                .with_for_update()
            )
            if row is None:
                raise SnapshotProjectionError("pending_snapshot_missing")
            if row.status == "acked":
                return row
            row.status = "acked"
            row.acked_at = self._clock().astimezone(UTC)
            self._audit(
                session,
                row,
                "configuration_snapshot.ack",
                {"configVersion": row.config_version, "status": "acked"},
            )
            session.commit()
            return row


class ConfigurationSnapshotSync:
    """One-network-operation-per-tick selected configuration sender."""

    def __init__(
        self,
        repository: ConfigurationSnapshotRepository,
        identity_provider,
        identity_store,
        central,
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.identity_provider = identity_provider
        self.identity_store = identity_store
        self.central = central
        self.clock = clock
        self._lock = RLock()

    def _material(self) -> tuple[dict[str, Any], str, str] | None:
        try:
            identity = self.identity_provider()
            expires = datetime.fromisoformat(identity["certificateNotAfter"].replace("Z", "+00:00"))
            eligible = (
                identity.get("status") == "paired"
                and all(
                    identity.get(field)
                    for field in (
                        "installationId",
                        "credentialId",
                        "activeSpkiSha256",
                        "certificateSha256",
                    )
                )
                and expires.tzinfo is not None
                and expires.astimezone(UTC) > self.clock().astimezone(UTC)
            )
            if not eligible:
                return None
            certificate, chain = self.identity_store.read_identity_credential()
            private_key = self.identity_store.identity_private_pem()
            return identity, certificate + chain, private_key
        except (KeyError, TypeError, ValueError, OSError, UnicodeError, RuntimeError):
            return None

    @staticmethod
    def _valid_accepted(response: dict[str, Any], pending: ConfigurationSnapshot) -> bool:
        expected_keys = {
            "status",
            "snapshotId",
            "installationId",
            "configVersion",
            "projectionSha256",
            "acceptedAt",
            "activePointCount",
        }
        if not isinstance(response, dict) or set(response) != expected_keys:
            return False
        try:
            accepted_at = datetime.fromisoformat(response["acceptedAt"].replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            return False
        return (
            response["status"] == "accepted"
            and response["snapshotId"] == pending.snapshot_id
            and response["installationId"] == pending.installation_id
            and type(response["configVersion"]) is int
            and response["configVersion"] == pending.config_version
            and response["projectionSha256"] == pending.projection_sha256
            and accepted_at.tzinfo is not None
            and type(response["activePointCount"]) is int
            and response["activePointCount"] >= 0
        )

    @staticmethod
    def _status_matches(response: dict[str, Any], pending: ConfigurationSnapshot) -> bool | None:
        if not isinstance(response, dict):
            raise ConfigurationSyncError("invalid_configuration_status_response")
        if set(response) == {"status", "installationId"} and response["status"] == "none":
            if response["installationId"] not in {None, pending.installation_id}:
                raise ConfigurationSyncError("invalid_configuration_status_response")
            return False
        expected = {
            "status",
            "installationId",
            "configVersion",
            "projectionSha256",
            "acceptedAt",
            "activePointCount",
        }
        if set(response) != expected or response.get("status") != "accepted":
            raise ConfigurationSyncError("invalid_configuration_status_response")
        if response.get("installationId") != pending.installation_id:
            raise ConfigurationSyncError("configuration_status_binding_mismatch")
        version = response.get("configVersion")
        count = response.get("activePointCount")
        try:
            accepted = datetime.fromisoformat(response["acceptedAt"].replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            raise ConfigurationSyncError("invalid_configuration_status_response") from None
        if (
            type(version) is not int
            or type(count) is not int
            or count < 0
            or accepted.tzinfo is None
        ):
            raise ConfigurationSyncError("invalid_configuration_status_response")
        if version < pending.config_version:
            return False
        if (
            version == pending.config_version
            and response.get("projectionSha256") == pending.projection_sha256
        ):
            return True
        return None

    def run_once(self) -> str:
        with self._lock:
            material = self._material()
            if material is None:
                return "ineligible"
            identity, certificate, private_key = material
            pending = self.repository.pending()
            if pending is None:
                pending = self.repository.prepare(identity["installationId"])
                if pending is None:
                    return "unchanged"
            if pending.installation_id != identity["installationId"]:
                raise ConfigurationSyncError("snapshot_identity_binding_mismatch")
            if pending.needs_status_check:
                try:
                    status = self.central.configuration_status(certificate, private_key)
                except Exception as error:
                    raise ConfigurationSyncError("configuration_status_unreachable") from error
                matches = self._status_matches(status, pending)
                if matches is True:
                    self.repository.ack(pending.snapshot_id)
                    return "acked"
                if matches is None:
                    raise ConfigurationSyncError("ambiguous_configuration_status")
                self.repository.record_status_checked(pending.snapshot_id)
                return "retry_pending"
            pending = self.repository.record_attempt(pending.snapshot_id)
            try:
                response = self.central.upload_configuration_snapshot(
                    pending.payload, certificate, private_key
                )
            except Exception as error:
                raise ConfigurationSyncError("configuration_upload_unreachable") from error
            if not self._valid_accepted(response, pending):
                raise ConfigurationSyncError("invalid_configuration_snapshot_response")
            self.repository.ack(pending.snapshot_id)
            return "acked"
