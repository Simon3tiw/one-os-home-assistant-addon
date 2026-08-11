from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import secrets
from datetime import UTC, datetime

from sqlalchemy import select

from .models import Point
from .reconciliation import evidence, project_capability, quality, reconcile, record_evidence
from .telemetry_outbox import TelemetryOutboxError


class SyncCoordinator:
    """Single owner for snapshots, subscriptions, reconnects and database writes."""

    def __init__(
        self,
        ha,
        session_factory,
        *,
        full_interval: float = 300,
        registry_debounce: float = 1,
        base_backoff: float = 1,
        max_backoff: float = 60,
        jitter: float = 0.2,
        telemetry_outbox=None,
    ):
        self.ha = ha
        self.session_factory = session_factory
        self.telemetry_outbox = telemetry_outbox
        self.full_interval = full_interval
        self.registry_debounce = registry_debounce
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self.jitter = jitter
        self.generation = 0
        self.reconnects = 0
        self.last_error: str | None = None
        self.last_full_sync: str | None = None
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._reconcile_lock = asyncio.Lock()

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self.run(), name="one-os-ha-sync")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def reconcile_once(self, generation: int | None = None) -> None:
        async with self._reconcile_lock:
            if generation is not None and generation != self.generation:
                return
            snapshot = await self.ha.snapshot()
            if generation is not None and generation != self.generation:
                return
            with self.session_factory() as db:
                reconcile(db, snapshot, actor="connector")
            self.last_full_sync = datetime.now(UTC).isoformat()

    async def apply_state_event(self, event: dict, generation: int) -> bool:
        if generation != self.generation:
            return False
        state = event.get("new_state") or event.get("data", {}).get("new_state")
        if not isinstance(state, dict) or not isinstance(state.get("entity_id"), str):
            return False
        with self.session_factory() as db:
            point = db.scalar(select(Point).where(Point.current_entity_id == state["entity_id"]))
            if not point or generation != self.generation:
                return False
            raw_attributes = state.get("attributes")
            attrs = raw_attributes if isinstance(raw_attributes, dict) else {}
            entity = {
                "entity_id": state["entity_id"],
                "entity_category": json.loads(point.evidence_json).get("entityCategory"),
            }
            ev = evidence(entity, state)
            ev_json = json.dumps(ev, sort_keys=True, separators=(",", ":"))
            ev_hash = hashlib.sha256(ev_json.encode()).hexdigest()
            if point.evidence_hash and point.evidence_hash != ev_hash:
                point.cloud_control_enabled = False
                point.capability_review_required = True
            state_quality = quality(state)
            stored_telemetry = None
            if self.telemetry_outbox is not None:
                try:
                    stored_telemetry = self.telemetry_outbox.append_state(
                        point_id=point.id,
                        raw_value=state.get("state"),
                        quality=state_quality,
                        observed_at=state.get("last_updated"),
                        db_session=db,
                    )
                except TelemetryOutboxError as exc:
                    if str(exc) not in {
                        "acked_snapshot_missing",
                        "point_not_in_acked_snapshot",
                        "point_not_telemetry_eligible",
                    }:
                        raise
            try:
                point.raw_value = state.get("state")
                point.attributes_json = json.dumps(attrs)
                point.updated_at = state.get("last_updated")
                point.quality = state_quality
                point.source_unit = attrs.get("unit_of_measurement")
                point.evidence_json = ev_json
                point.evidence_hash = ev_hash
                point.capability_json = json.dumps(project_capability(ev))
                point.lifecycle = "active"
                point.revision += 1
                record_evidence(db, point, ev_json, ev_hash)
                db.commit()
            except Exception:
                db.rollback()
                if stored_telemetry is not None and self.telemetry_outbox is not None:
                    self.telemetry_outbox.abort_before_commit(stored_telemetry)
                raise
            if stored_telemetry is not None and self.telemetry_outbox is not None:
                self.telemetry_outbox.finalize_after_commit(stored_telemetry)
        return True

    async def _consume_states(self, generation: int) -> None:
        async for event in self.ha.subscribe_state_events():
            if generation != self.generation or self._stop.is_set():
                return
            await self.apply_state_event(event, generation)
        raise ConnectionError("state subscription ended")

    async def _consume_registry(self, generation: int) -> None:
        async for _event in self.ha.subscribe_registry_events():
            if generation != self.generation or self._stop.is_set():
                return
            await asyncio.sleep(self.registry_debounce)
            await self.reconcile_once(generation)
        raise ConnectionError("registry subscription ended")

    async def _periodic(self, generation: int) -> None:
        while not self._stop.is_set() and generation == self.generation:
            await asyncio.sleep(self.full_interval)
            await self.reconcile_once(generation)

    async def _wait_backoff(self, attempt: int) -> None:
        delay = min(self.max_backoff, self.base_backoff * (2 ** min(attempt, 8)))
        delay *= 1 + secrets.SystemRandom().uniform(-self.jitter, self.jitter)
        try:
            await asyncio.wait_for(self._stop.wait(), max(0, delay))
        except TimeoutError:
            pass

    async def run(self) -> None:
        attempt = 0
        while not self._stop.is_set():
            self.generation += 1
            generation = self.generation
            tasks: list[asyncio.Task] = []
            try:
                await self.reconcile_once(generation)
                self.ha.connector_presence = "online"
                self.last_error = None
                attempt = 0
                tasks = [
                    asyncio.create_task(self._consume_states(generation)),
                    asyncio.create_task(self._consume_registry(generation)),
                    asyncio.create_task(self._periodic(generation)),
                ]
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.ha.connector_presence = "offline"
                self.last_error = type(exc).__name__
                self.reconnects += 1
                await self._wait_backoff(attempt)
                attempt += 1
            finally:
                for task in tasks:
                    task.cancel()
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
