from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from alembic import command
from alembic.config import Config
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

from .ha.client import HomeAssistantReadOnlyClient
from .ha.fake import IncompatibleHomeAssistant, UnavailableHomeAssistant
from .models import (
    Asset,
    Audit,
    PhysicalDevice,
    Point,
    Property,
    Site,
    SourceBinding,
    Space,
    Structure,
    SyncRun,
    uid,
)
from .reconciliation import reconcile
from .sync import SyncCoordinator


class OverrideBody(BaseModel):
    revision: int
    displayName: str | None = None
    displayUnit: str | None = None
    decimals: int | None = None
    ontologyClass: str | None = None
    tags: list[str] | None = None


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


def migrate_database(database_url: str) -> None:
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
        "tags": json.loads(point.tags_json),
        "evidence": json.loads(point.evidence_json),
        "capability": json.loads(point.capability_json),
    }


def inventory(db):
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
    return {"structures": structures, "flatPoints": flat, "counts": counts}


def create_app(
    database_url=None,
    ha_client=None,
    ingress_proxies=None,
    allowed_origins=None,
    csrf_ttl_seconds=600,
    start_background_sync=False,
    sync_interval=300,
):
    app = FastAPI(
        title="ONE.OS commissioning API", version="1.0.0", root_path=os.getenv("INGRESS_PATH", "")
    )
    url = database_url or os.getenv("DATABASE_URL", "sqlite:////tmp/one-os-commissioning.db")
    migrate_database(url)
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

    @asynccontextmanager
    async def lifespan(_app):
        if start_background_sync:
            app.state.sync = SyncCoordinator(
                app.state.ha,
                app.state.session,
                full_interval=sync_interval,
            )
            await app.state.sync.start()
        try:
            yield
        finally:
            if app.state.sync:
                await app.state.sync.stop()
            engine.dispose()

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
            origin = request.headers.get("origin", "").rstrip("/")
            parsed_origin = urlparse(origin)
            valid_web_origin = (
                parsed_origin.scheme in {"http", "https"}
                and bool(parsed_origin.netloc)
                and parsed_origin.username is None
                and parsed_origin.password is None
            )
            origin_allowed = origin in trusted_origins if trusted_origins else valid_web_origin
            if not origin_allowed or request.headers.get("sec-fetch-site") != "same-origin":
                return JSONResponse({"error": {"code": "same_origin_required"}}, 403)
            token = request.headers.get("x-csrf-token")
            record = app.state.csrf.get(user)
            if not token or not record or record[0] != token or record[1] < time.monotonic():
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
        token = secrets.token_urlsafe(32)
        app.state.csrf[request.state.user_id] = (
            token,
            time.monotonic() + app.state.csrf_ttl_seconds,
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
                "phaseNotice": "Cloud pairing and data transport follow in Phase 2B/2C",
                "database": "healthy",
            }

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
            if target.lifecycle == "archived":
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
                if not target or target.lifecycle == "archived":
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
            return {
                "schemaVersion": "1.0",
                "softwareVersion": "0.1.2",
                "architecture": platform.machine(),
                "installationHash": hashlib.sha256(
                    (site.installation_id if site else "uninitialized").encode()
                ).hexdigest(),
                "databaseRevision": "0002",
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
            }

    static_dir = os.getenv("STATIC_DIR")
    if static_dir and os.path.isdir(static_dir):
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="ui")
    return app


app = create_app(start_background_sync=True)
