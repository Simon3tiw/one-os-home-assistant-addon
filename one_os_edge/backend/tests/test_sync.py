import asyncio
import time

import pytest
from fastapi.testclient import TestClient
from one_os_addon.app import create_app
from one_os_addon.ha.fake import FakeHomeAssistant
from one_os_addon.models import Point
from one_os_addon.sync import SyncCoordinator


class StreamingFakeHomeAssistant(FakeHomeAssistant):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.state_events = asyncio.Queue()
        self.registry_events = asyncio.Queue()
        self.snapshot_count = 0
        self.state_subscription_count = 0
        self.fail_state_subscriptions = 0

    async def snapshot(self):
        self.snapshot_count += 1
        return await super().snapshot()

    async def subscribe_state_events(self):
        self.state_subscription_count += 1
        if self.fail_state_subscriptions:
            self.fail_state_subscriptions -= 1
            raise ConnectionError("scripted disconnect")
        while True:
            yield await self.state_events.get()

    async def subscribe_registry_events(self):
        while True:
            yield await self.registry_events.get()


async def eventually(predicate, timeout=2):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


def streaming_fake():
    base = FakeHomeAssistant.standard()
    return StreamingFakeHomeAssistant(
        floors=base.floors,
        areas=base.areas,
        devices=base.devices,
        entities=base.entities,
        states=base.states,
        users=base.users,
    )


@pytest.mark.asyncio
async def test_sync_owner_discovers_on_start_and_applies_live_state(tmp_path):
    fake = streaming_fake()
    app = create_app(database_url=f"sqlite:///{tmp_path / 'sync.db'}", ha_client=fake)
    coordinator = SyncCoordinator(
        fake,
        app.state.session,
        full_interval=60,
        registry_debounce=0,
        base_backoff=0.01,
        jitter=0,
    )

    await coordinator.start()
    await eventually(lambda: fake.snapshot_count >= 1)
    await fake.state_events.put(
        {
            "event_type": "state_changed",
            "data": {
                "new_state": {
                    "entity_id": "sensor.room_temperature",
                    "state": "22.5",
                    "last_updated": "2026-08-04T12:00:00Z",
                    "attributes": {
                        "friendly_name": "Room temperature",
                        "unit_of_measurement": "°C",
                    },
                }
            },
        }
    )

    def value_updated():
        with app.state.session() as db:
            point = db.query(Point).filter_by(current_entity_id="sensor.room_temperature").one()
            return point.raw_value == "22.5"

    await eventually(value_updated)
    await coordinator.stop()
    assert coordinator._task is None
    app.state.engine.dispose()


@pytest.mark.asyncio
async def test_registry_event_reconciles_and_disconnect_reconnects(tmp_path):
    fake = streaming_fake()
    fake.fail_state_subscriptions = 1
    app = create_app(database_url=f"sqlite:///{tmp_path / 'reconnect.db'}", ha_client=fake)
    coordinator = SyncCoordinator(
        fake,
        app.state.session,
        full_interval=60,
        registry_debounce=0,
        base_backoff=0.01,
        max_backoff=0.01,
        jitter=0,
    )

    await coordinator.start()
    await eventually(lambda: coordinator.reconnects >= 1 and fake.snapshot_count >= 2)
    current_generation = coordinator.generation
    assert not await coordinator.apply_state_event({}, current_generation - 1)

    fake.entities.append(
        {
            "entity_id": "sensor.new",
            "unique_id": "new-1",
            "platform": "demo",
            "config_entry_id": "entry-1",
            "device_id": None,
            "area_id": None,
            "name": "New sensor",
            "entity_category": None,
        }
    )
    fake.states["sensor.new"] = {
        "state": "1",
        "last_updated": "2026-08-04T12:01:00Z",
        "attributes": {},
    }
    await fake.registry_events.put({"event_type": "entity_registry_updated", "data": {}})

    def new_point_exists():
        with app.state.session() as db:
            return db.query(Point).filter_by(current_entity_id="sensor.new").count() == 1

    await eventually(new_point_exists)
    await coordinator.stop()
    app.state.engine.dispose()


def test_fastapi_lifespan_owns_startup_discovery_and_shutdown(tmp_path):
    fake = streaming_fake()
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'lifespan.db'}",
        ha_client=fake,
        start_background_sync=True,
        sync_interval=60,
    )

    with TestClient(app):
        deadline = time.monotonic() + 2
        while fake.snapshot_count < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        with app.state.session() as db:
            assert db.query(Point).count() == 3
        coordinator = app.state.sync
        assert coordinator._task is not None

    assert coordinator._task is None
