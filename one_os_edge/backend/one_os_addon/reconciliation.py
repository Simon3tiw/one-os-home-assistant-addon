from __future__ import annotations

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    Asset,
    Audit,
    CapabilityEvidenceSnapshot,
    PhysicalDevice,
    Point,
    Site,
    SourceBinding,
    Space,
    Structure,
    SyncRun,
    uid,
)


def stable_entity_key(entity):
    if entity.get("unique_id"):
        return "entity:" + "|".join(
            str(entity.get(k) or "") for k in ("platform", "config_entry_id", "unique_id")
        )
    return "temporary:" + entity["entity_id"]


def quality(state):
    if not state:
        return "unknown"
    if state.get("state") == "unavailable":
        return "unavailable"
    if state.get("state") == "unknown":
        return "unknown"
    return "good"


def evidence(entity, state):
    attrs = (state or {}).get("attributes", {})
    domain = entity["entity_id"].split(".", 1)[0]
    return {
        "domain": domain,
        "supportedFeatures": attrs.get("supported_features", 0),
        "min": attrs.get("min"),
        "max": attrs.get("max"),
        "step": attrs.get("step"),
        "options": attrs.get("options") or [],
        "entityCategory": entity.get("entity_category"),
    }


ADAPTER_VERSION = "ha-2025.1-v2"


def project_capability(ev):
    domain = ev["domain"]
    high = domain in {
        "lock",
        "alarm_control_panel",
        "script",
        "automation",
        "scene",
        "button",
        "update",
        "cover",
    }
    supported = ev.get("supportedFeatures")
    evidence_valid = type(supported) is int and supported >= 0
    actions = []
    constraints = {}
    if evidence_valid and not high and domain in {"light", "switch"}:
        actions = ["set_power"]
    if evidence_valid and not high and domain == "climate" and supported & 1:
        minimum, maximum, step = ev.get("min"), ev.get("max"), ev.get("step")
        numeric = all(type(value) in {int, float} for value in (minimum, maximum, step))
        if numeric and minimum < maximum and 0 < step <= maximum - minimum:
            actions = ["set_temperature"]
            constraints["set_temperature"] = {
                "minimum": minimum,
                "maximum": maximum,
                "step": step,
            }
    return {
        "schemaVersion": "1.0",
        "adapterVersion": ADAPTER_VERSION,
        "actions": actions,
        "constraints": constraints,
        "technicallyControllable": bool(actions),
        "highRisk": high,
        "immutable": True,
    }


def record_evidence(db, point, evidence_json, evidence_hash):
    existing = db.scalar(
        select(CapabilityEvidenceSnapshot).where(
            CapabilityEvidenceSnapshot.point_id == point.id,
            CapabilityEvidenceSnapshot.evidence_hash == evidence_hash,
        )
    )
    if not existing:
        db.add(
            CapabilityEvidenceSnapshot(
                id=uid("evidence"),
                point_id=point.id,
                evidence_hash=evidence_hash,
                evidence_json=evidence_json,
                adapter_version=ADAPTER_VERSION,
            )
        )


def ensure_binding(db, kind, registry_id, object_id):
    found = db.scalar(
        select(SourceBinding).where(
            SourceBinding.registry_kind == kind,
            SourceBinding.registry_id == registry_id,
            SourceBinding.active.is_(True),
        )
    )
    if found and found.object_id != object_id:
        raise ValueError("source_binding_conflict")
    if not found:
        db.add(
            SourceBinding(
                id=uid("bind"), registry_kind=kind, registry_id=registry_id, object_id=object_id
            )
        )


def reconcile(db: Session, snapshot: dict, actor="system"):
    site = db.scalar(select(Site))
    if not site:
        site = Site(
            id=uid("site"), installation_id="local-installation", name="Home Assistant installation"
        )
        db.add(site)
        db.flush()
    structures = {}
    seen_structures = set()
    for floor in sorted(snapshot["floors"], key=lambda x: x["floor_id"]):
        key = "floor:" + floor["floor_id"]
        obj = db.scalar(select(Structure).where(Structure.source_key == key))
        if not obj:
            obj = Structure(
                id=uid("str"),
                site_id=site.id,
                parent_id=None,
                type="Floor",
                name=floor["name"],
                source_key=key,
            )
            db.add(obj)
            db.flush()
        obj.name = floor["name"]
        obj.lifecycle = "active"
        structures[floor["floor_id"]] = obj
        seen_structures.add(key)
        ensure_binding(db, "floor", floor["floor_id"], obj.id)
    unassigned = db.scalar(select(Structure).where(Structure.source_key == "synthetic:unassigned"))
    if not unassigned:
        unassigned = Structure(
            id=uid("str"),
            site_id=site.id,
            parent_id=None,
            type="Unassigned",
            name="Unassigned",
            source_key="synthetic:unassigned",
        )
        db.add(unassigned)
        db.flush()
    spaces = {}
    seen_spaces = set()
    for area in sorted(snapshot["areas"], key=lambda x: x["area_id"]):
        key = "area:" + area["area_id"]
        parent = structures.get(area.get("floor_id"), unassigned)
        obj = db.scalar(select(Space).where(Space.source_key == key))
        if not obj:
            obj = Space(
                id=uid("spc"),
                structure_id=parent.id,
                type="Room",
                name=area["name"],
                source_key=key,
            )
            db.add(obj)
            db.flush()
        obj.structure_id = parent.id
        obj.name = area["name"]
        obj.lifecycle = "active"
        spaces[area["area_id"]] = obj
        seen_spaces.add(key)
        ensure_binding(db, "area", area["area_id"], obj.id)
    unassigned_space = db.scalar(select(Space).where(Space.source_key == "synthetic:unassigned"))
    if not unassigned_space:
        unassigned_space = Space(
            id=uid("spc"),
            structure_id=unassigned.id,
            type="Unassigned",
            name="Unassigned",
            source_key="synthetic:unassigned",
        )
        db.add(unassigned_space)
        db.flush()
    devices = {}
    assets = {}
    seen_devices = set()
    seen_assets = set()
    entity_areas_by_device: dict[str, set[str]] = {}
    for entity in snapshot["entities"]:
        if entity.get("device_id") and entity.get("area_id"):
            entity_areas_by_device.setdefault(entity["device_id"], set()).add(entity["area_id"])
    for device in sorted(snapshot["devices"], key=lambda x: x["id"]):
        key = "device:" + device["id"]
        physical = db.scalar(select(PhysicalDevice).where(PhysicalDevice.source_key == key))
        if not physical:
            physical = PhysicalDevice(
                id=uid("dev"), name=device.get("name") or device["id"], source_key=key
            )
            db.add(physical)
            db.flush()
        physical.name = device.get("name") or device["id"]
        if physical.lifecycle != "archived":
            physical.lifecycle = "active"
        devices[device["id"]] = physical
        seen_devices.add(key)
        ensure_binding(db, "device", device["id"], physical.id)
        asset = db.scalar(select(Asset).where(Asset.source_key == key))
        source_space = spaces.get(device.get("area_id"))
        placement_conflict = bool(device.get("area_id") and not source_space)
        if not device.get("area_id"):
            entity_areas = entity_areas_by_device.get(device["id"], set())
            if len(entity_areas) == 1:
                source_space = spaces.get(next(iter(entity_areas)))
                placement_conflict = source_space is None
            elif len(entity_areas) > 1:
                placement_conflict = True
        source_space = source_space or unassigned_space
        if not asset:
            asset = Asset(
                id=uid("ast"),
                space_id=source_space.id,
                source_space_id=source_space.id,
                physical_device_id=physical.id,
                name=physical.name,
                source_key=key,
            )
            db.add(asset)
            db.flush()
        asset.source_space_id = source_space.id
        if not asset.placement_override:
            asset.space_id = source_space.id
        asset.placement_conflict = placement_conflict
        if not asset.name_override:
            asset.name = physical.name
        if asset.lifecycle != "archived":
            asset.lifecycle = "active"
        assets[device["id"]] = asset
        seen_assets.add(key)
    seen_points = set()
    for entity in sorted(snapshot["entities"], key=lambda x: x["entity_id"]):
        key = stable_entity_key(entity)
        state = snapshot["states"].get(entity["entity_id"])
        asset = assets.get(entity.get("device_id"))
        if not asset:
            asset = db.scalar(select(Asset).where(Asset.source_key == key + ":asset"))
            source_space = spaces.get(entity.get("area_id"), unassigned_space)
            if not asset:
                asset = Asset(
                    id=uid("ast"),
                    space_id=source_space.id,
                    source_space_id=source_space.id,
                    physical_device_id=None,
                    name=entity.get("name") or entity["entity_id"],
                    source_key=key + ":asset",
                )
                db.add(asset)
                db.flush()
            asset.source_space_id = source_space.id
            if not asset.placement_override:
                asset.space_id = source_space.id
            asset.placement_conflict = bool(
                entity.get("area_id") and entity.get("area_id") not in spaces
            )
            if asset.lifecycle != "archived":
                asset.lifecycle = "active"
            seen_assets.add(key + ":asset")
        point = db.scalar(select(Point).where(Point.source_key == key))
        if not point:
            point = db.scalar(
                select(Point).where(
                    Point.current_entity_id == entity["entity_id"],
                    Point.binding_stability == "temporary",
                )
            )
            if point:
                point.source_key = key
                point.binding_stability = "stable"
                point.temporary_accepted = False
                point.review_status = "unreviewed"
                point.cloud_control_enabled = False
                point.capability_review_required = True
        attrs = (state or {}).get("attributes", {})
        ev = evidence(entity, state)
        ev_json = json.dumps(ev, sort_keys=True, separators=(",", ":"))
        ev_hash = hashlib.sha256(ev_json.encode()).hexdigest()
        cap = project_capability(ev)
        source_device = next(
            (device for device in snapshot["devices"] if device["id"] == entity.get("device_id")),
            None,
        )
        point_placement_conflict = bool(
            source_device
            and entity.get("area_id")
            and entity.get("area_id") != source_device.get("area_id")
        )
        if not point:
            point = Point(
                id=uid("pnt"),
                asset_id=asset.id,
                source_asset_id=asset.id,
                source_key=key,
                registry_id=entity["entity_id"],
                current_entity_id=entity["entity_id"],
                source_name=attrs.get("friendly_name") or entity.get("name") or entity["entity_id"],
                source_unit=attrs.get("unit_of_measurement"),
                raw_value=(state or {}).get("state"),
                attributes_json=json.dumps(attrs),
                updated_at=(state or {}).get("last_updated"),
                quality=quality(state),
                evidence_json=ev_json,
                evidence_hash=ev_hash,
                capability_json=json.dumps(cap),
                placement_conflict=point_placement_conflict,
            )
            db.add(point)
            db.flush()
        else:
            if point.evidence_hash and point.evidence_hash != ev_hash:
                point.cloud_control_enabled = False
                point.capability_review_required = True
            point.source_asset_id = asset.id
            if not point.placement_override:
                point.asset_id = asset.id
            point.placement_conflict = point_placement_conflict
            point.registry_id = entity["entity_id"]
            point.current_entity_id = entity["entity_id"]
            point.source_name = (
                attrs.get("friendly_name") or entity.get("name") or entity["entity_id"]
            )
            point.source_unit = attrs.get("unit_of_measurement")
            point.raw_value = (state or {}).get("state")
            point.attributes_json = json.dumps(attrs)
            point.updated_at = (state or {}).get("last_updated")
            point.quality = quality(state)
            point.evidence_json = ev_json
            point.evidence_hash = ev_hash
            point.capability_json = json.dumps(cap)
            if point.lifecycle != "archived":
                point.lifecycle = "active"
            point.revision += 1
        db.flush()
        record_evidence(db, point, ev_json, ev_hash)
        seen_points.add(key)
        ensure_binding(db, "entity", key, point.id)
    for state_id, state in snapshot["states"].items():
        if not any(e["entity_id"] == state_id for e in snapshot["entities"]):
            # state-only entries are deliberately visible but not selectable
            entity = {
                "entity_id": state_id,
                "name": state_id,
                "unique_id": None,
                "platform": None,
                "config_entry_id": None,
                "device_id": None,
                "area_id": None,
                "entity_category": None,
            }
            key = "temporary:" + state_id
            if key not in seen_points:
                asset = db.scalar(select(Asset).where(Asset.source_key == key + ":asset"))
                if not asset:
                    asset = Asset(
                        id=uid("ast"),
                        space_id=unassigned_space.id,
                        source_space_id=unassigned_space.id,
                        physical_device_id=None,
                        name=state_id,
                        source_key=key + ":asset",
                    )
                    db.add(asset)
                    db.flush()
                asset.source_space_id = unassigned_space.id
                if not asset.placement_override:
                    asset.space_id = unassigned_space.id
                if asset.lifecycle != "archived":
                    asset.lifecycle = "active"
                seen_assets.add(key + ":asset")
                ev = evidence(entity, state)
                ev_json = json.dumps(ev, sort_keys=True, separators=(",", ":"))
                ev_hash = hashlib.sha256(ev_json.encode()).hexdigest()
                cap = project_capability(ev)
                point = db.scalar(select(Point).where(Point.source_key == key))
                if not point:
                    point = Point(
                        id=uid("pnt"),
                        asset_id=asset.id,
                        source_asset_id=asset.id,
                        source_key=key,
                        registry_id=state_id,
                        current_entity_id=state_id,
                        source_name=state_id,
                        source_unit=state.get("attributes", {}).get("unit_of_measurement"),
                        raw_value=state["state"],
                        attributes_json=json.dumps(state.get("attributes", {})),
                        updated_at=state.get("last_updated"),
                        quality=quality(state),
                        evidence_json=ev_json,
                        evidence_hash=ev_hash,
                        capability_json=json.dumps(cap),
                        binding_stability="temporary",
                    )
                    db.add(point)
                else:
                    if point.evidence_hash and point.evidence_hash != ev_hash:
                        point.cloud_control_enabled = False
                        point.capability_review_required = True
                    point.source_asset_id = asset.id
                    if not point.placement_override:
                        point.asset_id = asset.id
                    point.current_entity_id = state_id
                    point.source_name = state_id
                    point.source_unit = state.get("attributes", {}).get("unit_of_measurement")
                    point.raw_value = state["state"]
                    point.attributes_json = json.dumps(state.get("attributes", {}))
                    point.updated_at = state.get("last_updated")
                    point.quality = quality(state)
                    point.evidence_json = ev_json
                    point.evidence_hash = ev_hash
                    point.capability_json = json.dumps(cap)
                    point.lifecycle = "active"
                    point.revision += 1
                db.flush()
                record_evidence(db, point, ev_json, ev_hash)
                seen_points.add(key)
    for structure in db.scalars(select(Structure)).all():
        if (
            not structure.source_key.startswith("synthetic:")
            and structure.source_key not in seen_structures
            and structure.lifecycle == "active"
        ):
            structure.lifecycle = "missing"
            structure.revision += 1
    for space in db.scalars(select(Space)).all():
        if (
            not space.source_key.startswith("synthetic:")
            and space.source_key not in seen_spaces
            and space.lifecycle == "active"
        ):
            space.lifecycle = "missing"
            space.revision += 1
    for physical in db.scalars(select(PhysicalDevice)).all():
        if physical.source_key not in seen_devices and physical.lifecycle == "active":
            physical.lifecycle = "missing"
            physical.revision += 1
    for asset in db.scalars(select(Asset)).all():
        if (
            not asset.source_key.startswith("manual:")
            and asset.source_key not in seen_assets
            and asset.lifecycle == "active"
        ):
            asset.lifecycle = "missing"
            asset.placement_conflict = True
            asset.revision += 1
    for point in db.scalars(select(Point)).all():
        if point.source_key not in seen_points and point.lifecycle == "active":
            point.lifecycle = "missing"
            point.cloud_control_enabled = False
            point.revision += 1
    run = SyncRun(id=uid("sync"), status="success", counts_json="{}")
    db.add(run)
    db.add(
        Audit(
            id=uid("audit"),
            actor_id=actor,
            action="reconcile",
            object_id=site.id,
            revision=1,
            fields_json='["inventory"]',
        )
    )
    db.commit()
    return run
