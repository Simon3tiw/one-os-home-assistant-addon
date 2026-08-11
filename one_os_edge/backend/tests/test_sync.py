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


def test_telemetry_featureflag_recovers_before_background_sync_start(tmp_path, monkeypatch):
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    fake = streaming_fake()
    order = []
    original_recover = TelemetryOutbox.recover
    original_start = SyncCoordinator.start

    def observed_recover(self):
        order.append("recover")
        return original_recover(self)

    async def observed_start(self):
        assert order == ["recover"]
        order.append("sync-start")
        await original_start(self)

    monkeypatch.setattr(TelemetryOutbox, "recover", observed_recover)
    monkeypatch.setattr(SyncCoordinator, "start", observed_start)
    spool = tmp_path / "telemetry-outbox"
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'telemetry-lifespan.db'}",
        ha_client=fake,
        start_background_sync=True,
        sync_interval=60,
        pairing_backend=False,
        telemetry_enabled=True,
        telemetry_spool_dir=spool,
    )

    with TestClient(app):
        assert order == ["recover", "sync-start"]
        assert app.state.telemetry_outbox is not None
        assert app.state.sync.telemetry_outbox is app.state.telemetry_outbox
        assert app.state.telemetry_recovery == {
            "removedOrphans": 0,
            "truncatedSegments": 0,
            "convertedMissingRecords": 0,
        }

    assert app.state.sync._task is None


def test_telemetry_recovery_failure_blocks_all_background_sync(tmp_path, monkeypatch):
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    started = []

    def failed_recovery(_self):
        raise RuntimeError("corrupt telemetry spool")

    async def forbidden_start(_self):
        started.append(True)

    monkeypatch.setattr(TelemetryOutbox, "recover", failed_recovery)
    monkeypatch.setattr(SyncCoordinator, "start", forbidden_start)
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'failed-recovery.db'}",
        ha_client=streaming_fake(),
        pairing_backend=False,
        start_background_sync=True,
        telemetry_enabled=True,
        telemetry_spool_dir=tmp_path / "telemetry-outbox",
    )

    with pytest.raises(RuntimeError, match="corrupt telemetry spool"):
        with TestClient(app):
            pass

    assert started == []
    assert app.state.sync is None


def test_telemetry_delivery_worker_starts_after_recovery_and_stops_on_shutdown(
    tmp_path, monkeypatch
):
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    order = []
    original_recover = TelemetryOutbox.recover
    original_sync_stop = SyncCoordinator.stop

    def observed_recover(self):
        order.append("recover")
        return original_recover(self)

    async def observed_sync_stop(self):
        order.append("sync-stop")
        await original_sync_stop(self)

    class Worker:
        async def start(self):
            order.append("delivery-start")

        async def stop(self):
            order.append("delivery-stop")

    monkeypatch.setattr(TelemetryOutbox, "recover", observed_recover)
    monkeypatch.setattr(SyncCoordinator, "stop", observed_sync_stop)
    worker = Worker()
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'telemetry-worker-lifespan.db'}",
        ha_client=streaming_fake(),
        pairing_backend=False,
        telemetry_enabled=True,
        telemetry_spool_dir=tmp_path / "telemetry-outbox",
        telemetry_worker=worker,
        start_background_sync=True,
    )

    with TestClient(app):
        assert order == ["recover", "delivery-start"]
        assert app.state.telemetry_worker is worker

    assert order == ["recover", "delivery-start", "sync-stop", "delivery-stop"]


def test_real_pairing_boundary_auto_composes_delivery_worker_only_when_enabled(tmp_path):
    from one_os_addon.telemetry_worker import TelemetryDeliveryWorker

    enabled = create_app(
        database_url=f"sqlite:///{tmp_path / 'telemetry-auto-worker.db'}",
        ha_client=streaming_fake(),
        identity_dir=tmp_path / "identity-enabled",
        start_pairing_worker=False,
        telemetry_enabled=True,
        telemetry_spool_dir=tmp_path / "telemetry-enabled",
    )
    disabled = create_app(
        database_url=f"sqlite:///{tmp_path / 'telemetry-no-worker.db'}",
        ha_client=streaming_fake(),
        identity_dir=tmp_path / "identity-disabled",
        start_pairing_worker=False,
        telemetry_enabled=False,
    )

    with TestClient(enabled):
        assert isinstance(enabled.state.telemetry_worker, TelemetryDeliveryWorker)
        assert enabled.state.telemetry_worker._task is not None
    assert enabled.state.telemetry_worker._task is None

    with TestClient(disabled):
        assert disabled.state.telemetry_worker is None
        assert disabled.state.telemetry_delivery is None


def test_injected_delivery_worker_requires_enabled_featureflag(tmp_path):
    with pytest.raises(ValueError, match="requires telemetry feature flag"):
        create_app(
            database_url=f"sqlite:///{tmp_path / 'disabled-injected-worker.db'}",
            ha_client=streaming_fake(),
            pairing_backend=False,
            telemetry_enabled=False,
            telemetry_worker=object(),
        )


def test_lifespan_cleanup_continues_after_stop_callback_failure(tmp_path, monkeypatch):
    order = []

    class Worker:
        def __init__(self, name):
            self.name = name

        async def start(self):
            order.append(f"{self.name}-start")

        async def stop(self):
            order.append(f"{self.name}-stop")

    async def sync_start(_self):
        order.append("sync-start")

    async def sync_stop(_self):
        order.append("sync-stop")
        raise RuntimeError("stop failed")

    monkeypatch.setattr(SyncCoordinator, "start", sync_start)
    monkeypatch.setattr(SyncCoordinator, "stop", sync_stop)
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'cleanup-stop-failure.db'}",
        ha_client=streaming_fake(),
        pairing_backend=False,
        telemetry_enabled=True,
        telemetry_spool_dir=tmp_path / "cleanup-stop-failure-spool",
        telemetry_worker=Worker("telemetry"),
        start_background_sync=True,
    )
    app.state.pairing_worker = Worker("pairing")
    original_dispose = app.state.engine.dispose

    def dispose():
        order.append("dispose")
        original_dispose()

    monkeypatch.setattr(app.state.engine, "dispose", dispose)

    with pytest.raises(RuntimeError, match="stop failed"):
        with TestClient(app):
            pass

    assert order == [
        "pairing-start",
        "telemetry-start",
        "sync-start",
        "sync-stop",
        "telemetry-stop",
        "pairing-stop",
        "dispose",
    ]


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        ("recovery", ["recover", "dispose"]),
        ("pairing", ["recover", "pairing-start", "pairing-stop", "dispose"]),
        (
            "telemetry",
            [
                "recover",
                "pairing-start",
                "telemetry-start",
                "telemetry-stop",
                "pairing-stop",
                "dispose",
            ],
        ),
        (
            "sync",
            [
                "recover",
                "pairing-start",
                "telemetry-start",
                "sync-start",
                "sync-stop",
                "telemetry-stop",
                "pairing-stop",
                "dispose",
            ],
        ),
    ],
)
def test_failed_lifespan_startup_rolls_back_attempted_workers_in_reverse_order(
    tmp_path, monkeypatch, failure, expected
):
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    order = []

    class Worker:
        def __init__(self, name):
            self.name = name

        async def start(self):
            order.append(f"{self.name}-start")
            if failure == self.name:
                raise RuntimeError("startup failed")

        async def stop(self):
            order.append(f"{self.name}-stop")

    original_recover = TelemetryOutbox.recover

    def recover(self):
        order.append("recover")
        if failure == "recovery":
            raise RuntimeError("startup failed")
        return original_recover(self)

    async def sync_start(_self):
        order.append("sync-start")
        if failure == "sync":
            raise RuntimeError("startup failed")

    async def sync_stop(_self):
        order.append("sync-stop")

    monkeypatch.setattr(TelemetryOutbox, "recover", recover)
    monkeypatch.setattr(SyncCoordinator, "start", sync_start)
    monkeypatch.setattr(SyncCoordinator, "stop", sync_stop)
    app = create_app(
        database_url=f"sqlite:///{tmp_path / f'lifespan-{failure}.db'}",
        ha_client=streaming_fake(),
        pairing_backend=False,
        telemetry_enabled=True,
        telemetry_spool_dir=tmp_path / f"spool-{failure}",
        telemetry_worker=Worker("telemetry"),
        start_background_sync=True,
    )
    app.state.pairing_worker = Worker("pairing")
    original_dispose = app.state.engine.dispose

    def dispose():
        order.append("dispose")
        original_dispose()

    monkeypatch.setattr(app.state.engine, "dispose", dispose)

    with pytest.raises(RuntimeError, match="startup failed"):
        with TestClient(app):
            pass

    assert order == expected
