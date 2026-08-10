from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from one_os_addon.pairing_backend import PairingError
from one_os_addon.pairing_worker import PairingWorker


class WorkerBackend:
    def __init__(self, *, failures: int = 0, expired: bool = False) -> None:
        deadline = datetime.now(UTC) + (-timedelta(seconds=1) if expired else timedelta(minutes=1))
        self.state = {"status": "pop_verified", "codeExpiresAt": deadline.isoformat()}
        self.failures = failures
        self.refreshes = 0
        self.resets = []

    def status(self):
        return self.state.copy()

    def refresh(self):
        self.refreshes += 1
        if self.refreshes <= self.failures:
            raise PairingError("central_result_unreachable")
        self.state = {"status": "paired"}
        return self.state.copy()

    def maintain_device(self):
        self.maintenances = getattr(self, "maintenances", 0) + 1
        return self.state.copy()

    def reset(self, local_only=False, terminal="cancelled"):
        self.resets.append((local_only, terminal))
        self.state = {"status": terminal}


async def eventually(predicate, timeout: float = 1.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError("condition was not reached")
        await asyncio.sleep(0.001)


@pytest.mark.asyncio
async def test_worker_retries_with_bounded_full_jitter_and_stops_cleanly() -> None:
    backend = WorkerBackend(failures=2)
    bounds = []

    def shortest(low, high):
        bounds.append((low, high))
        return 0.001

    worker = PairingWorker(
        backend,
        poll_interval=0.001,
        base_backoff=1,
        max_backoff=30,
        random_uniform=shortest,
    )
    await worker.start()
    await eventually(lambda: backend.state["status"] == "paired")
    await worker.stop()

    assert backend.refreshes == 3
    assert bounds == [(1, 1), (1, 2)]
    assert worker.last_error is None
    assert worker._task is None


@pytest.mark.asyncio
async def test_worker_expires_locally_without_polling_central() -> None:
    backend = WorkerBackend(expired=True)
    worker = PairingWorker(backend, poll_interval=0.001)

    await worker.start()
    await eventually(lambda: backend.state["status"] == "expired")
    await worker.stop()

    assert backend.refreshes == 0
    assert backend.resets == [(True, "expired")]


class SnapshotSync:
    def __init__(self) -> None:
        self.calls = 0
        self.active = 0
        self.max_active = 0

    def run_once(self) -> str:
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            return "unchanged"
        finally:
            self.active -= 1


@pytest.mark.asyncio
async def test_worker_runs_configuration_only_while_paired_and_never_in_parallel() -> None:
    backend = WorkerBackend()
    backend.state = {"status": "unpaired"}
    snapshots = SnapshotSync()
    worker = PairingWorker(
        backend,
        poll_interval=0.001,
        configuration_sync=snapshots,
    )

    await worker.start()
    await asyncio.sleep(0.01)
    assert snapshots.calls == 0
    backend.state = {"status": "paired"}
    await eventually(lambda: snapshots.calls >= 2)
    backend.state = {"status": "revoked"}
    calls_at_revoke = snapshots.calls
    await asyncio.sleep(0.01)
    await worker.stop()

    assert snapshots.max_active == 1
    assert snapshots.calls == calls_at_revoke


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "compromise_error", ["device_generation_drift", "renewal_safety_window_missed"]
)
async def test_worker_checks_device_authority_before_snapshot_and_stops_on_compromise(
    compromise_error,
) -> None:
    backend = WorkerBackend()
    backend.state = {"status": "paired"}
    events: list[str] = []

    def maintain_device():
        events.append("status")
        backend.state = {"status": "compromised"}
        raise PairingError(compromise_error)

    backend.maintain_device = maintain_device
    snapshots = SnapshotSync()
    original = snapshots.run_once

    def snapshot():
        events.append("snapshot")
        return original()

    snapshots.run_once = snapshot
    worker = PairingWorker(backend, poll_interval=0.001, configuration_sync=snapshots)
    await worker.start()
    await eventually(lambda: worker.last_error == compromise_error)
    await worker.stop()

    assert events == ["status"]
    assert snapshots.calls == 0


@pytest.mark.asyncio
async def test_paired_device_authority_is_polled_on_its_own_bounded_schedule() -> None:
    backend = WorkerBackend()
    backend.state = {"status": "paired"}
    snapshots = SnapshotSync()
    worker = PairingWorker(
        backend,
        poll_interval=0.001,
        device_poll_interval=0.03,
        configuration_sync=snapshots,
    )

    await worker.start()
    await eventually(lambda: snapshots.calls >= 5)
    await worker.stop()

    assert backend.maintenances == 1
    assert snapshots.calls >= 5


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["claim_proved", "issuing"])
async def test_worker_terminalizes_restarted_issuance_after_its_deadline(status) -> None:
    backend = WorkerBackend()
    backend.state = {
        "status": status,
        "issuanceExpiresAt": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
    }
    worker = PairingWorker(backend, poll_interval=0.001)

    await worker.start()
    await eventually(lambda: backend.state["status"] == "expired")
    await worker.stop()

    assert backend.refreshes == 0
    assert backend.resets == [(True, "expired")]
