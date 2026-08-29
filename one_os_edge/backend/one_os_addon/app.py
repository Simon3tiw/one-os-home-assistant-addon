from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import time
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import UTC
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse
from uuid import uuid4

from alembic import command
from alembic.config import Config
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import create_engine, event, func, insert, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import sessionmaker

from .central_destination import (
    DiscoveryError,
    normalize_fingerprint,
    test_pinned_discovery,
    validate_https_origin,
)
from .central_pairing_client import CentralPairingHTTPClient, PairingRequestGate
from .configuration_snapshot import ConfigurationSnapshotRepository, ConfigurationSnapshotSync
from .ha.client import HomeAssistantReadOnlyClient
from .ha.fake import IncompatibleHomeAssistant, UnavailableHomeAssistant
from .legacy_upgrade import upgrade_legacy_sqlite
from .models import (
    Asset,
    Audit,
    CentralDestination,
    EdgeIdentity,
    PhysicalDevice,
    Point,
    Property,
    Site,
    SourceBinding,
    Space,
    Structure,
    SyncRun,
    TelemetryBatch,
    now,
    uid,
)
from .pairing_backend import PairingBackend, PairingError
from .pairing_crypto import sign_low_s
from .pairing_repository import PairingRepository
from .pairing_storage import IdentityStore
from .pairing_worker import PairingWorker
from .reconciliation import infer_ontology_class, reconcile
from .sync import SyncCoordinator
from .telemetry_authority import TelemetryAuthorityManager
from .telemetry_authority_cut import TelemetryAuthorityCutRepository
from .telemetry_delivery import TelemetryDeliveryJournal
from .telemetry_outbox import TelemetryOutbox
from .telemetry_renewal import TelemetryRenewalManager
from .telemetry_transport import TelemetryDestinationSnapshot, TelemetryUploadTransport
from .telemetry_worker import TelemetryDeliveryWorker
from .version import DATABASE_REVISION, RELEASE_VERSION


class OverrideBody(BaseModel):
    revision: int
    displayName: str | None = None
    displayUnit: str | None = None
    decimals: int | None = None
    ontologyClass: str | None = None
    tags: list[str] | None = None

    @field_validator("ontologyClass")
    @classmethod
    def validate_ontology_class(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value or len(value) > 512:
            raise ValueError("ontologyClass must be a non-empty URI of at most 512 characters")
        parsed = urlparse(value)
        if parsed.scheme == "https" and parsed.netloc:
            return value
        if parsed.scheme == "urn" and parsed.path:
            return value
        raise ValueError("ontologyClass must be an absolute HTTPS or URN URI")


class SelectionBody(BaseModel):
    intent: str
    review: bool = False


class ControlBody(BaseModel):
    revision: int
    enabled: bool


class SplitBody(BaseModel):
    revision: int
    name: str
    pointIds: list[str]


class MergeBody(BaseModel):
    revision: int
    otherAssetId: str


class AssetUpdateBody(BaseModel):
    revision: int
    name: str | None = None
    type: str | None = None
    spaceId: str | None = None


class PointPlacementBody(BaseModel):
    revision: int
    assetId: str


class RevisionBody(BaseModel):
    revision: int


class EmptyPairingBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConfirmedPairingBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: Literal[True]


class CentralDestinationBody(BaseModel):
    revision: int
    origin: str = Field(max_length=2048)
    certificateFingerprint: str

    @field_validator("origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        return validate_https_origin(value)

    @field_validator("certificateFingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        return normalize_fingerprint(value)


class PropertyCreateBody(BaseModel):
    key: str
    valueType: Literal["string", "number", "integer", "boolean", "date", "url"]
    value: Any


class PropertyUpdateBody(BaseModel):
    revision: int
    valueType: Literal["string", "number", "integer", "boolean", "date", "url"]
    value: Any


class ReplacementBody(BaseModel):
    revision: int
    replacementPointId: str
    confirmSemanticMatch: bool


class ArchiveBody(BaseModel):
    revision: int
    action: Literal["rehome", "cascade"]


MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def is_valid_web_origin(value: str) -> bool:
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        _port = parsed.port  # Materialize range and syntax validation.
    except ValueError:
        return False
    return bool(
        parsed.scheme in {"http", "https"}
        and hostname
        and not any(character.isspace() for character in parsed.netloc)
        and "%" not in parsed.netloc
        and parsed.username is None
        and parsed.password is None
        and not parsed.path
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
        and value == f"{parsed.scheme}://{parsed.netloc}"
    )


def migrate_database(
    database_url: str,
    identity_dir: Path | None = None,
    identity_recovery_authorized: bool = False,
) -> None:
    configured = os.getenv("ALEMBIC_CONFIG")
    candidates = [
        Path(configured) if configured else None,
        Path.cwd() / "alembic.ini",
        Path(__file__).resolve().parents[2] / "alembic.ini",
        Path("/app/alembic.ini"),
    ]
    config_path = next((path for path in candidates if path and path.is_file()), None)
    if config_path is None:
        raise RuntimeError("alembic configuration unavailable")
    config = Config(str(config_path))
    config.set_main_option("sqlalchemy.url", database_url)
    config.attributes["explicit_database_url"] = True
    if upgrade_legacy_sqlite(
        database_url,
        config_path,
        identity_dir,
        identity_recovery_authorized=identity_recovery_authorized,
    ):
        return
    command.upgrade(config, "head")


def audit(db, request, action, object_id, revision, fields):
    db.add(
        Audit(
            id=uid("audit"),
            actor_id=request.state.user_id,
            action=action,
            object_id=object_id,
            revision=revision,
            fields_json=json.dumps(fields),
        )
    )


def convert(value, source, display):
    if display in (None, source):
        return value
    if source == "°C" and display == "°F":
        return value * 9 / 5 + 32
    if source == "°F" and display == "°C":
        return (value - 32) * 5 / 9
    raise ValueError("incompatible_unit")


def formatted(point):
    if point.raw_value in {None, "unknown", "unavailable"}:
        return point.raw_value or "—"
    try:
        value = convert(float(point.raw_value), point.source_unit, point.display_unit)
        decimals = (
            point.decimals
            if point.decimals is not None
            else int(json.loads(point.attributes_json).get("suggested_display_precision", 2))
        )
        shown = f"{value:.{decimals}f}".rstrip("0").rstrip(".").replace(".", ",")
        return shown + (
            f" {point.display_unit or point.source_unit}"
            if point.display_unit or point.source_unit
            else ""
        )
    except (ValueError, TypeError):
        return str(point.raw_value)


def effective(point):
    return (
        point.selection_intent == "include"
        and point.review_status == "reviewed"
        and point.lifecycle == "active"
    )


def validate_property_value(value_type: str, value: Any) -> None:
    parsed = urlparse(value) if isinstance(value, str) else None
    valid = {
        "string": isinstance(value, str),
        "integer": type(value) is int,
        "number": type(value) in {int, float},
        "boolean": type(value) is bool,
        "date": isinstance(value, str) and bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", value)),
        "url": bool(parsed and parsed.scheme in {"http", "https"} and parsed.netloc),
    }
    if not valid.get(value_type, False):
        raise HTTPException(422, detail={"code": "invalid_property_value"})


def property_json(item: Property) -> dict:
    owner = next(
        (
            kind
            for kind in ("site", "structure", "space", "asset", "point")
            if getattr(item, f"{kind}_id")
        ),
        None,
    )
    return {
        "id": item.id,
        "revision": item.revision,
        "ownerKind": owner,
        "ownerId": getattr(item, f"{owner}_id") if owner else None,
        "key": item.key,
        "valueType": item.value_type,
        "value": json.loads(item.value_json),
    }


def central_destination_json(item: CentralDestination | None) -> dict:
    if item is None:
        return {
            "configured": False,
            "revision": 0,
            "origin": None,
            "certificateFingerprint": None,
            "configuredAt": None,
            "status": "not_configured",
        }
    configured_at = item.configured_at
    if configured_at.tzinfo is None:
        configured_at = configured_at.replace(tzinfo=UTC)
    return {
        "configured": True,
        "revision": item.revision,
        "origin": item.origin,
        "certificateFingerprint": item.certificate_fingerprint,
        "configuredAt": configured_at.isoformat(),
        "status": "configured",
    }


def point_json(point):
    return {
        "id": point.id,
        "revision": point.revision,
        "assetId": point.asset_id,
        "source": {
            "system": "home_assistant",
            "registryKind": "entity",
            "registryId": point.registry_id,
            "stableKey": point.source_key,
        },
        "sourceLifecycle": point.lifecycle,
        "reviewStatus": point.review_status,
        "selectionIntent": point.selection_intent,
        "effectiveSelected": effective(point),
        "valueQuality": point.quality,
        "cloudControlEnabled": point.cloud_control_enabled,
        "capabilityReviewRequired": point.capability_review_required,
        "bindingStability": point.binding_stability,
        "temporaryAccepted": point.temporary_accepted,
        "placementOverride": point.placement_override,
        "placementConflict": point.placement_conflict,
        "display": {
            "name": {
                "value": point.display_name or point.source_name,
                "provenance": "one_os_override" if point.display_name else "home_assistant",
            },
            "unit": {
                "value": point.display_unit or point.source_unit,
                "provenance": "one_os_override" if point.display_unit else "home_assistant",
            },
            "decimals": {
                "value": point.decimals,
                "provenance": "one_os_override" if point.decimals is not None else "home_assistant",
            },
        },
        "value": {
            "raw": point.raw_value,
            "formatted": formatted(point),
            "quality": point.quality,
            "updatedAt": point.updated_at,
        },
        "ontologyClass": point.ontology_class,
        "ontologyClassProvenance": point.ontology_class_source,
        "tags": json.loads(point.tags_json),
        "evidence": json.loads(point.evidence_json),
        "capability": json.loads(point.capability_json),
    }


def inventory(db):
    site = db.scalar(select(Site).limit(1))
    structures = []
    flat = []
    for s in db.scalars(
        select(Structure).where(Structure.lifecycle != "archived").order_by(Structure.name)
    ).all():
        spaces = []
        for sp in db.scalars(
            select(Space)
            .where(Space.structure_id == s.id, Space.lifecycle != "archived")
            .order_by(Space.name)
        ).all():
            assets = []
            for a in db.scalars(
                select(Asset)
                .where(Asset.space_id == sp.id, Asset.lifecycle != "archived")
                .order_by(Asset.name)
            ).all():
                points = [
                    point_json(p)
                    for p in db.scalars(
                        select(Point)
                        .where(Point.asset_id == a.id, Point.lifecycle != "archived")
                        .order_by(Point.source_name)
                    ).all()
                ]
                flat += points
                states = [p["effectiveSelected"] for p in points]
                state = (
                    "selected"
                    if states and all(states)
                    else "partial"
                    if any(states)
                    else "unselected"
                )
                assets.append(
                    {
                        "id": a.id,
                        "spaceId": a.space_id,
                        "name": a.name,
                        "type": a.type,
                        "revision": a.revision,
                        "sourceLifecycle": a.lifecycle,
                        "placementOverride": a.placement_override,
                        "placementConflict": a.placement_conflict,
                        "selectionState": state,
                        "physicalDeviceId": a.physical_device_id,
                        "points": points,
                    }
                )
            asset_states = [asset["selectionState"] for asset in assets]
            spaces.append(
                {
                    "id": sp.id,
                    "name": sp.name,
                    "type": sp.type,
                    "revision": sp.revision,
                    "sourceLifecycle": sp.lifecycle,
                    "selectionState": (
                        "selected"
                        if asset_states and all(state == "selected" for state in asset_states)
                        else "partial"
                        if any(state != "unselected" for state in asset_states)
                        else "unselected"
                    ),
                    "assets": assets,
                }
            )
        space_states = [space["selectionState"] for space in spaces]
        structures.append(
            {
                "id": s.id,
                "name": s.name,
                "type": s.type,
                "revision": s.revision,
                "sourceLifecycle": s.lifecycle,
                "selectionState": (
                    "selected"
                    if space_states and all(state == "selected" for state in space_states)
                    else "partial"
                    if any(state != "unselected" for state in space_states)
                    else "unselected"
                ),
                "spaces": spaces,
            }
        )
    counts = {
        "structures": db.scalar(select(func.count()).select_from(Structure)),
        "spaces": db.scalar(select(func.count()).select_from(Space)),
        "physicalDevices": db.scalar(select(func.count()).select_from(PhysicalDevice)),
        "assets": db.scalar(
            select(func.count()).select_from(Asset).where(Asset.lifecycle != "archived")
        ),
        "points": db.scalar(select(func.count()).select_from(Point)),
    }
    return {
        "site": {"id": site.id, "name": site.name} if site else None,
        "structures": structures,
        "flatPoints": flat,
        "counts": counts,
    }


def create_app(
    database_url=None,
    ha_client=None,
    ingress_proxies=None,
    allowed_origins=None,
    csrf_ttl_seconds=600,
    start_background_sync=False,
    sync_interval=300,
    destination_tester=None,
    identity_dir=None,
    pairing_backend=None,
    start_pairing_worker=True,
    telemetry_enabled=False,
    telemetry_spool_dir=None,
    telemetry_worker=None,
    telemetry_authority_enabled=False,
    identity_recovery_authorized=False,
):
    if telemetry_worker is not None and not telemetry_enabled:
        raise ValueError("telemetry worker requires telemetry feature flag")
    if telemetry_authority_enabled and (
        not telemetry_enabled or pairing_backend is not None or telemetry_worker is not None
    ):
        raise ValueError("telemetry authority requires built-in telemetry and pairing runtimes")
    app = FastAPI(
        title="ONE.OS commissioning API",
        version=RELEASE_VERSION,
        root_path=os.getenv("INGRESS_PATH", ""),
    )
    url = database_url or os.getenv("DATABASE_URL", "sqlite:////tmp/one-os-commissioning.db")
    identity_root = Path(identity_dir or os.getenv("IDENTITY_DIR", "/data/identity"))
    migrate_database(
        url,
        identity_root,
        identity_recovery_authorized=identity_recovery_authorized,
    )
    engine = create_engine(
        url,
        connect_args={"check_same_thread": False, "timeout": 5} if url.startswith("sqlite") else {},
    )
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def pragmas(conn, _):
            cur = conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.close()

    app.state.session = sessionmaker(engine, expire_on_commit=False)
    app.state.identity_dir = identity_root
    app.state.pairing = None
    app.state.pairing_worker = None
    app.state.configuration_snapshot_repository = ConfigurationSnapshotRepository(app.state.session)
    app.state.configuration_sync = None
    with app.state.session() as identity_session:
        if identity_session.get(EdgeIdentity, 1) is None:
            installation_id = str(uuid4())
            identity_session.add(
                EdgeIdentity(
                    id=1,
                    installation_id=installation_id,
                    status="unpaired",
                    revision=0,
                    telemetry_authorization_revision=1,
                    lineage_id=installation_id,
                )
            )
            identity_session.commit()
    supervisor_token = os.getenv("SUPERVISOR_TOKEN")
    app.state.ha = ha_client or (
        HomeAssistantReadOnlyClient(supervisor_token)
        if supervisor_token
        else UnavailableHomeAssistant()
    )
    app.state.ingress_proxies = ingress_proxies or {"172.30.32.2"}
    configured_origins = os.getenv("ALLOWED_ORIGINS")
    app.state.allowed_origins = (
        set(allowed_origins)
        if allowed_origins is not None
        else set(configured_origins.split(","))
        if configured_origins
        else None
    )
    app.state.csrf = {}
    app.state.csrf_ttl_seconds = csrf_ttl_seconds
    app.state.engine = engine
    app.state.sync = None
    telemetry_spool = Path(
        telemetry_spool_dir or os.getenv("TELEMETRY_SPOOL_DIR", "/data/telemetry-outbox")
    )
    app.state.telemetry_outbox = (
        TelemetryOutbox(
            app.state.session,
            telemetry_spool,
        )
        if telemetry_enabled
        else None
    )
    telemetry_destination = TelemetryDestinationSnapshot()
    with app.state.session() as destination_session:
        configured_destination = destination_session.get(CentralDestination, 1)
        if configured_destination is not None:
            telemetry_destination.update(
                configured_destination.revision,
                configured_destination.origin,
                configured_destination.certificate_fingerprint,
            )
    app.state.telemetry_destination = telemetry_destination
    app.state.telemetry_delivery = (
        TelemetryDeliveryJournal(app.state.session, telemetry_spool)
        if telemetry_enabled and not telemetry_authority_enabled
        else None
    )
    app.state.telemetry_worker = telemetry_worker if telemetry_enabled else None
    app.state.telemetry_authority = None
    app.state.telemetry_authority_cut = None
    app.state.telemetry_renewal = None
    app.state.telemetry_recovery = None
    app.state.destination_tester = destination_tester or test_pinned_discovery

    if pairing_backend is not False:
        if pairing_backend is None:

            def pairing_destination() -> tuple[str, str]:
                with app.state.session() as destination_session:
                    destination = destination_session.get(CentralDestination, 1)
                    if destination is None:
                        raise LookupError("central destination is not configured")
                    return destination.origin, destination.certificate_fingerprint

            central_pairing = CentralPairingHTTPClient(
                pairing_destination,
                gate=PairingRequestGate(interval=1.0, slots=2),
            )
            identity_store = IdentityStore(app.state.identity_dir)
            pairing_repository = PairingRepository(app.state.session)
            pairing_runtime = PairingBackend(
                identity_store,
                central_pairing,
                repository=pairing_repository,
            )
            app.state.pairing = pairing_runtime
            authority_manager = None
            if telemetry_authority_enabled:
                authority_manager = TelemetryAuthorityManager(
                    app.state.session,
                    central_pairing,
                    pairing_runtime.active_transport_identity,
                    lambda preimage: sign_low_s(identity_store.load_identity(), preimage),
                )
            renewal_manager = TelemetryRenewalManager(
                app.state.session,
                identity_store,
                central_pairing,
                pairing_runtime.active_transport_identity,
                lambda preimage: sign_low_s(identity_store.load_identity(), preimage),
                reactivate=authority_manager.activate if authority_manager is not None else None,
            )
            pairing_runtime.attach_renewal_v2_terminator(renewal_manager)
            if authority_manager is not None:
                app.state.telemetry_authority = authority_manager
                app.state.telemetry_authority_cut = TelemetryAuthorityCutRepository(
                    app.state.session
                )
                app.state.telemetry_renewal = renewal_manager
                pairing_runtime.attach_renewal_v2(renewal_manager)
                app.state.telemetry_delivery = TelemetryDeliveryJournal(
                    app.state.session,
                    telemetry_spool,
                    authority_manager=authority_manager,
                )
            app.state.configuration_sync = ConfigurationSnapshotSync(
                app.state.configuration_snapshot_repository,
                pairing_repository.load,
                identity_store,
                central_pairing,
            )
            if telemetry_enabled and app.state.telemetry_worker is None:
                telemetry_transport = TelemetryUploadTransport(telemetry_destination)
                telemetry_delivery = app.state.telemetry_delivery
                assert telemetry_delivery is not None
                app.state.telemetry_worker = TelemetryDeliveryWorker(
                    telemetry_delivery,
                    pairing_runtime.active_transport_identity,
                    pairing_runtime.mark_transport_revoked,
                    telemetry_transport,
                )
            if start_pairing_worker:
                app.state.pairing_worker = PairingWorker(
                    app.state.pairing,
                    configuration_sync=app.state.configuration_sync,
                )
        else:
            app.state.pairing = pairing_backend

    @asynccontextmanager
    async def lifespan(_app):
        async with AsyncExitStack() as cleanup:
            cleanup.callback(engine.dispose)
            if app.state.telemetry_outbox:
                app.state.telemetry_recovery = app.state.telemetry_outbox.recover()
            if app.state.telemetry_authority:
                app.state.telemetry_authority.activate()
            if app.state.pairing_worker:
                cleanup.push_async_callback(app.state.pairing_worker.stop)
                await app.state.pairing_worker.start()
            if app.state.telemetry_worker:
                cleanup.push_async_callback(app.state.telemetry_worker.stop)
                await app.state.telemetry_worker.start()
            if start_background_sync:
                app.state.sync = SyncCoordinator(
                    app.state.ha,
                    app.state.session,
                    full_interval=sync_interval,
                    telemetry_outbox=app.state.telemetry_outbox,
                )
                cleanup.push_async_callback(app.state.sync.stop)
                await app.state.sync.start()
            yield

    app.router.lifespan_context = lifespan

    @app.middleware("http")
    async def secure(request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        host = request.client.host if request.client else ""
        if host not in app.state.ingress_proxies:
            return JSONResponse({"error": {"code": "untrusted_ingress_proxy"}}, 403)
        user = request.headers.get("X-Remote-User-Id")
        if not user:
            return JSONResponse({"error": {"code": "missing_remote_user"}}, 401)
        try:
            is_admin = await app.state.ha.is_admin(user)
        except IncompatibleHomeAssistant:
            return JSONResponse({"error": {"code": "incompatible_home_assistant"}}, 503)
        if not is_admin:
            return JSONResponse({"error": {"code": "admin_required"}}, 403)
        request.state.user_id = user
        if request.method in MUTATING:
            try:
                trusted_origins = (
                    app.state.allowed_origins
                    if app.state.allowed_origins is not None
                    else await app.state.ha.trusted_origins()
                )
            except IncompatibleHomeAssistant:
                return JSONResponse({"error": {"code": "origin_verification_unavailable"}}, 503)
            origin = request.headers.get("origin", "")
            valid_web_origin = is_valid_web_origin(origin)
            origin_allowed = origin in trusted_origins if trusted_origins else valid_web_origin
            fetch_site = request.headers.get("sec-fetch-site")
            token = request.headers.get("x-csrf-token")
            record = app.state.csrf.get(user)
            token_valid = bool(
                token and record and record[0] == token and record[1] >= time.monotonic()
            )
            bound_origin = record[2] if record and len(record) > 2 else None
            same_origin_evidence = fetch_site == "same-origin" or (
                fetch_site in {None, "same-site"} and valid_web_origin and bound_origin == origin
            )
            if not origin_allowed or not same_origin_evidence:
                return JSONResponse({"error": {"code": "same_origin_required"}}, 403)
            if not token_valid:
                app.state.csrf.pop(user, None)
                return JSONResponse({"error": {"code": "csrf_invalid"}}, 403)
            if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
                return JSONResponse({"error": {"code": "json_required"}}, 415)
        return await call_next(request)

    def db():
        return app.state.session()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/v1/session")
    def session(request: Request):
        browser_origin = request.query_params.get("browserOrigin", "")
        if browser_origin and not is_valid_web_origin(browser_origin):
            raise HTTPException(400, detail={"code": "invalid_browser_origin"})
        token = secrets.token_urlsafe(32)
        app.state.csrf[request.state.user_id] = (
            token,
            time.monotonic() + app.state.csrf_ttl_seconds,
            browser_origin or None,
        )
        return {"csrfToken": token, "expiresIn": app.state.csrf_ttl_seconds}

    @app.get("/api/v1/overview")
    def overview():
        with db() as s:
            data = inventory(s)
            last = s.scalar(select(SyncRun).order_by(SyncRun.at.desc()))
            return {
                "connectorPresence": app.state.ha.connector_presence,
                "lastSync": last.at.isoformat() if last else None,
                "counts": data["counts"],
                "phaseNotice": (
                    "Secure pairing and configuration sync are active; "
                    "telemetry follows in Phase 2C"
                ),
                "database": "healthy",
            }

    def pairing_or_unavailable():
        if app.state.pairing is None:
            raise HTTPException(503, detail={"code": "pairing_unavailable"})
        return app.state.pairing

    def no_store(response: Response) -> None:
        response.headers["Cache-Control"] = "no-store"

    def pairing_failure(error: PairingError) -> HTTPException:
        code = str(error)
        unavailable = {
            "central_registration_unreachable",
            "central_proof_unreachable",
            "central_result_unreachable",
            "central_claim_proof_unreachable",
            "central_ack_unreachable",
        }
        return HTTPException(503 if code in unavailable else 409, detail={"code": code})

    @app.get("/api/v1/pairing/status")
    def pairing_status(response: Response):
        no_store(response)
        return pairing_or_unavailable().status()

    @app.get("/api/v1/pairing/code")
    def pairing_code(response: Response):
        no_store(response)
        try:
            return pairing_or_unavailable().code()
        except PairingError as error:
            raise pairing_failure(error) from None

    @app.post("/api/v1/pairing/start")
    def pairing_start(_body: EmptyPairingBody, response: Response, request: Request):
        no_store(response)
        pairing = pairing_or_unavailable()
        installation_id = pairing.status().get("installationId")
        if not installation_id:
            with db() as pairing_db:
                installation_id = pairing_db.get(EdgeIdentity, 1).installation_id
        try:
            return pairing.start("initial", installation_id, actor_id=f"ha:{request.state.user_id}")
        except PairingError as error:
            raise pairing_failure(error) from None

    @app.post("/api/v1/pairing/refresh")
    def pairing_refresh(_body: EmptyPairingBody, response: Response, request: Request):
        no_store(response)
        try:
            return pairing_or_unavailable().refresh(actor_id=f"ha:{request.state.user_id}")
        except PairingError as error:
            raise pairing_failure(error) from None

    @app.post("/api/v1/pairing/reset")
    def pairing_reset(_body: EmptyPairingBody, response: Response, request: Request):
        no_store(response)
        pairing = pairing_or_unavailable()
        try:
            pairing.reset(actor_id=f"ha:{request.state.user_id}")
            return pairing.status()
        except PairingError as error:
            raise pairing_failure(error) from None

    @app.post("/api/v1/pairing/cancel")
    def pairing_cancel(_body: ConfirmedPairingBody, response: Response, request: Request):
        no_store(response)
        try:
            return pairing_or_unavailable().cancel(actor_id=f"ha:{request.state.user_id}")
        except PairingError as error:
            raise pairing_failure(error) from None

    @app.post("/api/v1/pairing/rotate-key")
    def pairing_rotate_key(_body: ConfirmedPairingBody, response: Response, request: Request):
        no_store(response)
        try:
            return pairing_or_unavailable().rotate_key(actor_id=f"ha:{request.state.user_id}")
        except PairingError as error:
            raise pairing_failure(error) from None

    @app.post("/api/v1/pairing/replace-identity-after-restore")
    def pairing_replace_after_restore(
        _body: ConfirmedPairingBody, response: Response, request: Request
    ):
        no_store(response)
        pairing = pairing_or_unavailable()
        public = pairing.status()
        if public.get("status") != "identity_missing_after_restore":
            raise HTTPException(409, detail={"code": "restore_replacement_not_required"})
        try:
            return pairing.rotate_key(actor_id=f"ha:{request.state.user_id}")
        except PairingError as error:
            raise pairing_failure(error) from None

    @app.get("/api/v1/central-destination")
    def get_central_destination():
        with db() as s:
            return central_destination_json(s.get(CentralDestination, 1))

    @app.put("/api/v1/central-destination")
    def put_central_destination(body: CentralDestinationBody, request: Request):
        with db() as s:
            next_revision = body.revision + 1
            try:
                if body.revision == 0:
                    result = s.execute(
                        insert(CentralDestination).values(
                            id=1,
                            revision=next_revision,
                            origin=body.origin,
                            certificate_fingerprint=body.certificateFingerprint,
                            configured_at=now(),
                        )
                    )
                else:
                    result = s.execute(
                        update(CentralDestination)
                        .where(
                            CentralDestination.id == 1,
                            CentralDestination.revision == body.revision,
                        )
                        .values(
                            revision=next_revision,
                            origin=body.origin,
                            certificate_fingerprint=body.certificateFingerprint,
                            configured_at=now(),
                        )
                    )
                if result.rowcount != 1:
                    s.rollback()
                    raise HTTPException(409, detail={"code": "revision_conflict"})
                audit(
                    s,
                    request,
                    "central_destination.configure",
                    "central_destination",
                    next_revision,
                    ["origin", "certificateFingerprint"],
                )
                s.commit()
            except HTTPException:
                raise
            except (IntegrityError, OperationalError) as error:
                s.rollback()
                raise HTTPException(409, detail={"code": "revision_conflict"}) from error
            destination = s.get(CentralDestination, 1)
            assert destination is not None
            app.state.telemetry_destination.update(
                next_revision, body.origin, body.certificateFingerprint
            )
            return central_destination_json(destination)

    @app.post("/api/v1/central-destination/test")
    def test_central_destination():
        with db() as s:
            destination = s.get(CentralDestination, 1)
            if destination is None:
                raise HTTPException(409, detail={"code": "not_configured"})
            origin = destination.origin
            fingerprint = destination.certificate_fingerprint
            tested_revision = destination.revision
        try:
            discovery = app.state.destination_tester(origin, fingerprint)
        except DiscoveryError as error:
            code = str(error)
            status_code = 503 if code == "unreachable" else 502
            raise HTTPException(status_code, detail={"code": code}) from None
        with db() as s:
            current = s.get(CentralDestination, 1)
            if current is None or current.revision != tested_revision:
                raise HTTPException(409, detail={"code": "revision_conflict"})
        return {"status": "reachable", "revision": tested_revision, **discovery}

    @app.post("/api/v1/reconcile")
    async def run_reconcile(request: Request):
        try:
            snap = await app.state.ha.snapshot()
        except IncompatibleHomeAssistant:
            raise HTTPException(503, detail={"code": "incompatible_home_assistant"}) from None
        with db() as s:
            run = reconcile(s, snap, request.state.user_id)
            return {"status": "success", "runId": run.id}

    @app.get("/api/v1/inventory")
    def get_inventory():
        with db() as s:
            return inventory(s)

    @app.get("/api/v1/points/{point_id}")
    def get_point(point_id: str):
        with db() as s:
            p = s.get(Point, point_id)
            if not p:
                raise HTTPException(404, detail={"code": "not_found"})
            return point_json(p)

    @app.patch("/api/v1/points/{point_id}/overrides")
    def override(point_id: str, body: OverrideBody, request: Request):
        with db() as s:
            p = s.get(Point, point_id)
            if not p:
                raise HTTPException(404)
            if p.revision != body.revision:
                raise HTTPException(409, detail={"code": "revision_conflict"})
            if body.displayUnit is not None:
                try:
                    convert(0, p.source_unit, body.displayUnit)
                except ValueError:
                    raise HTTPException(422, detail={"code": "incompatible_unit"}) from None
            fields = []
            for field, value in (
                ("display_name", body.displayName),
                ("display_unit", body.displayUnit),
                ("decimals", body.decimals),
                ("ontology_class", body.ontologyClass),
            ):
                if value is not None:
                    setattr(p, field, value)
                    fields.append(field)
            if body.ontologyClass is not None:
                p.ontology_class_source = "one_os_override"
            if body.tags is not None:
                p.tags_json = json.dumps(body.tags)
                fields.append("tags")
            p.revision += 1
            audit(s, request, "point.override", p.id, p.revision, fields)
            s.commit()
            return point_json(p)

    @app.delete("/api/v1/points/{point_id}/overrides/{field}")
    def reset_override(point_id: str, field: str, revision: int, request: Request):
        mapping = {
            "displayName": "display_name",
            "displayUnit": "display_unit",
            "decimals": "decimals",
            "ontologyClass": "ontology_class",
            "tags": "tags_json",
        }
        if field not in mapping:
            raise HTTPException(422)
        with db() as s:
            p = s.get(Point, point_id)
            if not p or p.revision != revision:
                raise HTTPException(409)
            if field == "ontologyClass":
                if p.ontology_class_source != "one_os_override":
                    raise HTTPException(422, "ontology_override_required")
                inferred = infer_ontology_class(json.loads(p.evidence_json))
                p.ontology_class = inferred
                p.ontology_class_source = "home_assistant_inferred" if inferred else "unset"
            else:
                setattr(p, mapping[field], "[]" if field == "tags" else None)
            p.revision += 1
            audit(s, request, "point.override.reset", p.id, p.revision, [field])
            s.commit()
            return point_json(p)

    @app.post("/api/v1/selection/{kind}/{object_id}")
    def selection(kind: str, object_id: str, body: SelectionBody, request: Request):
        if body.intent not in {"include", "exclude", "unset"}:
            raise HTTPException(422)
        with db() as s:
            if kind == "point":
                points = [s.get(Point, object_id)]
            elif kind == "asset":
                points = s.scalars(select(Point).where(Point.asset_id == object_id)).all()
            elif kind == "space":
                points = s.scalars(
                    select(Point)
                    .join(Asset, Point.asset_id == Asset.id)
                    .where(Asset.space_id == object_id)
                ).all()
            elif kind == "structure":
                points = s.scalars(
                    select(Point)
                    .join(Asset, Point.asset_id == Asset.id)
                    .join(Space, Asset.space_id == Space.id)
                    .where(Space.structure_id == object_id)
                ).all()
            else:
                raise HTTPException(422)
            if not points or points[0] is None:
                raise HTTPException(404)
            if body.intent == "include" and any(
                p.binding_stability == "temporary" and not p.temporary_accepted for p in points
            ):
                raise HTTPException(422, detail={"code": "temporary_binding_not_accepted"})
            if (
                body.intent == "include"
                and any(p.review_status == "unreviewed" for p in points)
                and not body.review
            ):
                raise HTTPException(422, detail={"code": "review_confirmation_required"})
            for p in points:
                p.selection_intent = body.intent
                p.review_status = "reviewed" if body.review else p.review_status
                p.revision += 1
            audit(
                s,
                request,
                "selection.bulk",
                object_id,
                max(p.revision for p in points),
                ["selectionIntent", "reviewStatus"],
            )
            s.commit()
            states = [effective(p) for p in points]
            return {
                "state": "selected" if all(states) else "partial" if any(states) else "unselected"
            }

    @app.patch("/api/v1/points/{point_id}/control")
    def control(point_id: str, body: ControlBody, request: Request):
        with db() as s:
            p = s.get(Point, point_id)
            if not p or p.revision != body.revision:
                raise HTTPException(409)
            cap = json.loads(p.capability_json)
            if body.enabled and (
                not cap["technicallyControllable"]
                or cap["highRisk"]
                or p.lifecycle != "active"
                or p.placement_conflict
                or p.binding_stability != "stable"
            ):
                raise HTTPException(422, detail={"code": "control_not_permitted"})
            p.cloud_control_enabled = body.enabled
            p.capability_review_required = False
            p.revision += 1
            audit(s, request, "control.permission", p.id, p.revision, ["cloudControlEnabled"])
            s.commit()
            return point_json(p)

    @app.patch("/api/v1/points/{point_id}/placement")
    def move_point(point_id: str, body: PointPlacementBody, request: Request):
        with db() as s:
            point = s.get(Point, point_id)
            target = s.get(Asset, body.assetId)
            if not point or not target:
                raise HTTPException(404)
            if point.revision != body.revision:
                raise HTTPException(409, detail={"code": "revision_conflict"})
            if point.lifecycle != "active" or target.lifecycle != "active":
                raise HTTPException(422, detail={"code": "invalid_asset"})
            point.asset_id = target.id
            point.placement_override = True
            point.placement_conflict = False
            point.revision += 1
            audit(s, request, "point.move", point.id, point.revision, ["assetId"])
            s.commit()
            return point_json(point)

    @app.post("/api/v1/points/{point_id}/accept-temporary-binding")
    def accept_temporary_binding(point_id: str, body: RevisionBody, request: Request):
        with db() as s:
            point = s.get(Point, point_id)
            if not point:
                raise HTTPException(404)
            if point.revision != body.revision:
                raise HTTPException(409, detail={"code": "revision_conflict"})
            if point.binding_stability != "temporary":
                raise HTTPException(422, detail={"code": "binding_is_stable"})
            point.temporary_accepted = True
            point.review_status = "unreviewed"
            point.cloud_control_enabled = False
            point.revision += 1
            audit(s, request, "point.temporary.accept", point.id, point.revision, ["binding"])
            s.commit()
            return point_json(point)

    @app.patch("/api/v1/assets/{asset_id}")
    def update_asset(asset_id: str, body: AssetUpdateBody, request: Request):
        with db() as s:
            asset = s.get(Asset, asset_id)
            if not asset:
                raise HTTPException(404)
            if asset.revision != body.revision:
                raise HTTPException(409, detail={"code": "revision_conflict"})
            if asset.lifecycle != "active":
                raise HTTPException(422, detail={"code": "invalid_asset"})
            fields = []
            if body.name is not None:
                asset.name = body.name
                asset.name_override = True
                fields.append("name")
            if body.type is not None:
                asset.type = body.type
                fields.append("type")
            if body.spaceId is not None:
                target = s.get(Space, body.spaceId)
                if not target or target.lifecycle != "active":
                    raise HTTPException(422, detail={"code": "invalid_space"})
                asset.space_id = target.id
                asset.placement_override = True
                asset.placement_conflict = False
                fields.append("spaceId")
            if not fields:
                raise HTTPException(422, detail={"code": "empty_update"})
            asset.revision += 1
            audit(s, request, "asset.update", asset.id, asset.revision, fields)
            s.commit()
            return {
                "id": asset.id,
                "revision": asset.revision,
                "name": asset.name,
                "type": asset.type,
                "spaceId": asset.space_id,
                "placementOverride": asset.placement_override,
            }

    owner_models = {
        "site": Site,
        "structure": Structure,
        "space": Space,
        "asset": Asset,
        "point": Point,
    }

    @app.get("/api/v1/properties/{kind}/{object_id}")
    def list_properties(kind: str, object_id: str):
        model = owner_models.get(kind)
        if not model:
            raise HTTPException(422)
        with db() as s:
            if not s.get(model, object_id):
                raise HTTPException(404)
            column = getattr(Property, f"{kind}_id")
            return [
                property_json(item)
                for item in s.scalars(
                    select(Property).where(column == object_id).order_by(Property.key)
                ).all()
            ]

    @app.post("/api/v1/properties/{kind}/{object_id}")
    def create_property(kind: str, object_id: str, body: PropertyCreateBody, request: Request):
        model = owner_models.get(kind)
        if not model or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", body.key):
            raise HTTPException(422)
        validate_property_value(body.valueType, body.value)
        with db() as s:
            if not s.get(model, object_id):
                raise HTTPException(404)
            owner_column = getattr(Property, f"{kind}_id")
            if s.scalar(
                select(Property).where(owner_column == object_id, Property.key == body.key)
            ):
                raise HTTPException(409, detail={"code": "property_exists"})
            item = Property(
                id=uid("prop"),
                key=body.key,
                value_type=body.valueType,
                value_json=json.dumps(body.value),
                **{f"{kind}_id": object_id},
            )
            s.add(item)
            s.flush()
            audit(s, request, "property.create", item.id, item.revision, ["key", "value"])
            s.commit()
            return property_json(item)

    @app.patch("/api/v1/properties/{property_id}")
    def update_property(property_id: str, body: PropertyUpdateBody, request: Request):
        validate_property_value(body.valueType, body.value)
        with db() as s:
            item = s.get(Property, property_id)
            if not item:
                raise HTTPException(404)
            if item.revision != body.revision:
                raise HTTPException(409, detail={"code": "revision_conflict"})
            item.value_type = body.valueType
            item.value_json = json.dumps(body.value)
            item.revision += 1
            audit(s, request, "property.update", item.id, item.revision, ["value"])
            s.commit()
            return property_json(item)

    @app.delete("/api/v1/properties/{property_id}")
    def delete_property(property_id: str, revision: int, request: Request):
        with db() as s:
            item = s.get(Property, property_id)
            if not item:
                raise HTTPException(404)
            if item.revision != revision:
                raise HTTPException(409, detail={"code": "revision_conflict"})
            audit(s, request, "property.delete", item.id, item.revision + 1, ["property"])
            s.delete(item)
            s.commit()
            return {"deleted": True}

    @app.post("/api/v1/lifecycle/points/{point_id}/replace")
    def replace_point(point_id: str, body: ReplacementBody, request: Request):
        if not body.confirmSemanticMatch or point_id == body.replacementPointId:
            raise HTTPException(422, detail={"code": "semantic_confirmation_required"})
        with db() as s:
            point = s.get(Point, point_id)
            replacement = s.get(Point, body.replacementPointId)
            if not point or not replacement:
                raise HTTPException(404)
            if point.revision != body.revision:
                raise HTTPException(409, detail={"code": "revision_conflict"})
            if (
                point.lifecycle != "missing"
                or replacement.lifecycle != "active"
                or replacement.binding_stability != "stable"
            ):
                raise HTTPException(422, detail={"code": "invalid_replacement"})
            replacement_binding = s.scalar(
                select(SourceBinding).where(
                    SourceBinding.object_id == replacement.id,
                    SourceBinding.registry_kind == "entity",
                    SourceBinding.active.is_(True),
                )
            )
            if not replacement_binding:
                raise HTTPException(409, detail={"code": "replacement_binding_conflict"})
            for binding in s.scalars(
                select(SourceBinding).where(
                    SourceBinding.object_id == point.id,
                    SourceBinding.registry_kind == "entity",
                    SourceBinding.active.is_(True),
                )
            ).all():
                binding.active = False
            old_source_key = point.source_key
            replacement_source_key = replacement.source_key
            replacement.source_key = "replaced:" + uid("source")
            replacement.lifecycle = "archived"
            replacement.cloud_control_enabled = False
            s.flush()
            replacement_binding.object_id = point.id
            for field in (
                "registry_id",
                "current_entity_id",
                "source_name",
                "source_unit",
                "raw_value",
                "attributes_json",
                "updated_at",
                "quality",
                "evidence_json",
                "evidence_hash",
                "capability_json",
                "source_asset_id",
            ):
                setattr(point, field, getattr(replacement, field))
            point.source_key = replacement_source_key
            if not point.placement_override:
                point.asset_id = replacement.asset_id
            point.lifecycle = "active"
            point.review_status = "unreviewed"
            point.cloud_control_enabled = False
            point.capability_review_required = True
            point.revision += 1
            audit(
                s,
                request,
                "point.replace",
                point.id,
                point.revision,
                ["sourceBinding", "reviewStatus", old_source_key],
            )
            s.commit()
            return point_json(point)

    @app.get("/api/v1/lifecycle/{kind}/{object_id}/archive-preview")
    def archive_preview(kind: str, object_id: str):
        with db() as s:
            if kind == "assets":
                target = s.get(Asset, object_id)
                points = s.scalars(select(Point).where(Point.asset_id == object_id)).all()
            elif kind == "spaces":
                target = s.get(Space, object_id)
                points = s.scalars(
                    select(Point)
                    .join(Asset, Point.asset_id == Asset.id)
                    .where(Asset.space_id == object_id)
                ).all()
            elif kind == "structures":
                target = s.get(Structure, object_id)
                points = s.scalars(
                    select(Point)
                    .join(Asset, Point.asset_id == Asset.id)
                    .join(Space, Asset.space_id == Space.id)
                    .where(Space.structure_id == object_id)
                ).all()
            else:
                raise HTTPException(422)
            if not target or target.source_key.startswith("synthetic:"):
                raise HTTPException(404)
            active = [point for point in points if point.lifecycle == "active"]
            return {
                "id": target.id,
                "revision": target.revision,
                "activeDescendants": len(active),
                "allowedActions": ["rehome", "cascade"] if active else ["cascade"],
            }

    @app.post("/api/v1/lifecycle/{kind}/{object_id}/archive")
    def archive_object(kind: str, object_id: str, body: ArchiveBody, request: Request):
        with db() as s:
            if kind == "assets":
                target = s.get(Asset, object_id)
                points = s.scalars(select(Point).where(Point.asset_id == object_id)).all()
                if body.action == "rehome" and points:
                    unassigned_space = s.scalar(
                        select(Space).where(Space.source_key == "synthetic:unassigned")
                    )
                    rehome = s.scalar(
                        select(Asset).where(Asset.source_key == "synthetic:archive-rehome")
                    )
                    if not rehome:
                        rehome = Asset(
                            id=uid("ast"),
                            space_id=unassigned_space.id,
                            source_space_id=unassigned_space.id,
                            name="Unassigned",
                            type="Unassigned",
                            source_key="synthetic:archive-rehome",
                            placement_override=True,
                        )
                        s.add(rehome)
                        s.flush()
                    for point in points:
                        if point.lifecycle == "active":
                            point.asset_id = rehome.id
                            point.placement_override = True
                            point.revision += 1
                elif body.action == "cascade":
                    for point in points:
                        point.lifecycle = "archived"
                        point.cloud_control_enabled = False
                        point.revision += 1
            elif kind == "spaces":
                target = s.get(Space, object_id)
                assets = s.scalars(select(Asset).where(Asset.space_id == object_id)).all()
                if body.action == "rehome":
                    unassigned_space = s.scalar(
                        select(Space).where(Space.source_key == "synthetic:unassigned")
                    )
                    for asset in assets:
                        if asset.lifecycle == "active":
                            asset.space_id = unassigned_space.id
                            asset.placement_override = True
                            asset.revision += 1
                else:
                    for asset in assets:
                        asset.lifecycle = "archived"
                        asset.revision += 1
                        for point in s.scalars(
                            select(Point).where(Point.asset_id == asset.id)
                        ).all():
                            point.lifecycle = "archived"
                            point.cloud_control_enabled = False
                            point.revision += 1
            elif kind == "structures":
                target = s.get(Structure, object_id)
                spaces = s.scalars(select(Space).where(Space.structure_id == object_id)).all()
                if body.action == "rehome":
                    unassigned = s.scalar(
                        select(Structure).where(Structure.source_key == "synthetic:unassigned")
                    )
                    for space in spaces:
                        if space.lifecycle == "active":
                            space.structure_id = unassigned.id
                            space.revision += 1
                else:
                    for space in spaces:
                        space.lifecycle = "archived"
                        space.revision += 1
                        for asset in s.scalars(
                            select(Asset).where(Asset.space_id == space.id)
                        ).all():
                            asset.lifecycle = "archived"
                            asset.revision += 1
                            for point in s.scalars(
                                select(Point).where(Point.asset_id == asset.id)
                            ).all():
                                point.lifecycle = "archived"
                                point.cloud_control_enabled = False
                                point.revision += 1
            else:
                raise HTTPException(422)
            if not target or target.source_key.startswith("synthetic:"):
                raise HTTPException(404)
            if target.revision != body.revision:
                raise HTTPException(409, detail={"code": "revision_conflict"})
            target.lifecycle = "archived"
            target.revision += 1
            audit(s, request, f"{kind}.archive", target.id, target.revision, [body.action])
            s.commit()
            return {"id": target.id, "sourceLifecycle": target.lifecycle}

    @app.post("/api/v1/assets/{asset_id}/split")
    def split(asset_id: str, body: SplitBody, request: Request):
        with db() as s:
            source = s.get(Asset, asset_id)
            if not source or source.revision != body.revision:
                raise HTTPException(409)
            points = s.scalars(
                select(Point).where(Point.id.in_(body.pointIds), Point.asset_id == asset_id)
            ).all()
            if len(points) != len(body.pointIds) or not points:
                raise HTTPException(422)
            target = Asset(
                id=uid("ast"),
                space_id=source.space_id,
                source_space_id=source.source_space_id,
                physical_device_id=source.physical_device_id,
                name=body.name,
                source_key="manual:" + uid("split"),
                placement_override=True,
            )
            s.add(target)
            s.flush()
            for p in points:
                p.asset_id = target.id
                p.placement_override = True
                p.revision += 1
            source.revision += 1
            audit(s, request, "asset.split", source.id, source.revision, ["points"])
            s.commit()
            return {
                "assetId": target.id,
                "sourceRevision": source.revision,
                "pointIds": [p.id for p in points],
            }

    @app.post("/api/v1/assets/{asset_id}/merge")
    def merge(asset_id: str, body: MergeBody, request: Request):
        with db() as s:
            target = s.get(Asset, asset_id)
            other = s.get(Asset, body.otherAssetId)
            if (
                not target
                or not other
                or target.revision != body.revision
                or other.lifecycle == "archived"
            ):
                raise HTTPException(409)
            points = s.scalars(select(Point).where(Point.asset_id.in_([target.id, other.id]))).all()
            for p in points:
                p.asset_id = target.id
                p.placement_override = True
                p.revision += 1
            other.lifecycle = "archived"
            target.revision += 1
            audit(s, request, "asset.merge", target.id, target.revision, ["points"])
            s.commit()
            return {"assetId": target.id, "pointIds": [p.id for p in points]}

    @app.get("/api/v1/audit")
    def audits():
        with db() as s:
            return [
                {
                    "actorId": a.actor_id,
                    "at": a.at.isoformat(),
                    "action": a.action,
                    "objectId": a.object_id,
                    "revision": a.revision,
                    "fields": json.loads(a.fields_json),
                }
                for a in s.scalars(select(Audit).order_by(Audit.at.desc())).all()
            ]

    @app.get("/api/v1/diagnostics/export")
    def diagnostics():
        with db() as s:
            data = inventory(s)
            site = s.scalar(select(Site))
            last = s.scalar(select(SyncRun).order_by(SyncRun.at.desc()))
            delivery_counts = {
                status: count
                for status, count in s.execute(
                    select(TelemetryBatch.status, func.count())
                    .group_by(TelemetryBatch.status)
                    .order_by(TelemetryBatch.status)
                )
            }
            oldest_quarantine = s.scalar(
                select(TelemetryBatch)
                .where(TelemetryBatch.status == "quarantined")
                .order_by(TelemetryBatch.quarantined_at, TelemetryBatch.batch_id)
                .limit(1)
            )
            return {
                "schemaVersion": "1.0",
                "softwareVersion": RELEASE_VERSION,
                "architecture": platform.machine(),
                "installationHash": hashlib.sha256(
                    (site.installation_id if site else "uninitialized").encode()
                ).hexdigest(),
                "databaseRevision": DATABASE_REVISION,
                "connectorPresence": app.state.ha.connector_presence,
                "lastSync": {
                    "at": last.at.isoformat() if last else None,
                    "status": last.status if last else "never",
                },
                "counts": data["counts"],
                "storage": {
                    "auditRecords": s.scalar(select(func.count()).select_from(Audit)),
                    "configurationBytes": 0,
                },
                "telemetryDelivery": {
                    "pending": delivery_counts.get("pending", 0),
                    "leased": delivery_counts.get("leased", 0),
                    "acked": delivery_counts.get("acked", 0),
                    "quarantined": delivery_counts.get("quarantined", 0),
                    "oldestQuarantine": (
                        {
                            "at": oldest_quarantine.quarantined_at.isoformat(),
                            "reason": oldest_quarantine.terminal_reason,
                        }
                        if oldest_quarantine is not None
                        and oldest_quarantine.quarantined_at is not None
                        else None
                    ),
                },
            }

    static_dir = os.getenv("STATIC_DIR")
    if static_dir and os.path.isdir(static_dir):
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="ui")
    return app


app = create_app(
    start_background_sync=True,
    telemetry_enabled=os.getenv("ONE_OS_TELEMETRY_ENABLED", "false").strip().lower() == "true",
    telemetry_authority_enabled=(
        os.getenv("ONE_OS_TELEMETRY_AUTHORITY_ENABLED", "false").strip().lower() == "true"
    ),
    identity_recovery_authorized=(
        os.getenv("ONE_OS_IDENTITY_RECOVERY_AUTHORIZED", "false").strip().lower() == "true"
    ),
)
