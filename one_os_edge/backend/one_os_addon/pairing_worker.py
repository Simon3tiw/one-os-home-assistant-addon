from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from .pairing_backend import PairingError

_ACTIVE = {
    "registering",
    "registered",
    "pop_verified",
    "claimed",
    "claim_proved",
    "issuing",
    "issued",
}
_DEADLINE_BY_STATUS: dict[str, str] = {
    "registering": "registrationExpiresAt",
    "registered": "registrationExpiresAt",
    "pop_verified": "codeExpiresAt",
    "claimed": "claimExpiresAt",
    "claim_proved": "issuanceExpiresAt",
    "issuing": "issuanceExpiresAt",
    "issued": "ackExpiresAt",
}


class WorkerBackend(Protocol):
    def status(self) -> dict[str, Any]: ...

    def refresh(self) -> dict[str, Any]: ...

    def maintain_device(self) -> dict[str, Any]: ...

    def reset(self, local_only: bool = False, terminal: str = "cancelled") -> None: ...


class ConfigurationSync(Protocol):
    def run_once(self) -> str: ...


class PairingWorker:
    """Single restart-aware poller with bounded exponential full-jitter backoff."""

    def __init__(
        self,
        backend: WorkerBackend,
        *,
        poll_interval: float = 1.0,
        device_poll_interval: float = 30.0,
        base_backoff: float = 1.0,
        max_backoff: float = 30.0,
        random_uniform: Callable[[float, float], float] | None = None,
        clock: Callable[[], datetime] | None = None,
        configuration_sync: ConfigurationSync | None = None,
    ) -> None:
        if (
            poll_interval <= 0
            or device_poll_interval <= 0
            or base_backoff <= 0
            or max_backoff < base_backoff
        ):
            raise ValueError("invalid pairing worker limits")
        self.backend = backend
        self.poll_interval = poll_interval
        self.device_poll_interval = device_poll_interval
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self._uniform = random_uniform or secrets.SystemRandom().uniform
        self._clock = clock or (lambda: datetime.now(UTC))
        self.configuration_sync = configuration_sync
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.last_error: str | None = None

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="edge-pairing-worker")

    async def stop(self) -> None:
        self._stop.set()
        task, self._task = self._task, None
        if task is not None:
            await task

    async def _wait(self, delay: float) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=delay)
        except TimeoutError:
            pass

    def _expired(self, state: dict[str, Any]) -> bool:
        field = _DEADLINE_BY_STATUS.get(state.get("status"))
        if field is None:
            return False
        value = state.get(field)
        if not isinstance(value, str):
            return False
        try:
            deadline = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return True
        return deadline.tzinfo is None or deadline.astimezone(UTC) <= self._clock().astimezone(UTC)

    async def _run(self) -> None:
        failures = 0
        next_device_poll = 0.0
        while not self._stop.is_set():
            try:
                state = self.backend.status()
                status = state.get("status")
                if status == "paired":
                    now = asyncio.get_running_loop().time()
                    if now >= next_device_poll:
                        await asyncio.to_thread(self.backend.maintain_device)
                        next_device_poll = now + self.device_poll_interval
                        state = self.backend.status()
                        if state.get("status") != "paired":
                            self.last_error = None
                            failures = 0
                            continue
                    if self.configuration_sync is not None:
                        await asyncio.to_thread(self.configuration_sync.run_once)
                    self.last_error = None
                    failures = 0
                    await self._wait(self.poll_interval)
                    continue
                if status not in _ACTIVE:
                    failures = 0
                    await self._wait(self.poll_interval)
                    continue
                if self._expired(state):
                    await asyncio.to_thread(self.backend.reset, local_only=True, terminal="expired")
                    self.last_error = None
                    failures = 0
                    continue
                await asyncio.to_thread(self.backend.refresh)
                self.last_error = None
                failures = 0
                await self._wait(self.poll_interval)
            except PairingError as error:
                self.last_error = str(error)
                failures += 1
                await self._wait(self._backoff(failures))
            except Exception as error:  # fail closed and keep the bounded worker alive
                self.last_error = type(error).__name__
                failures += 1
                await self._wait(self._backoff(failures))

    def _backoff(self, failures: int) -> float:
        ceiling = min(self.max_backoff, self.base_backoff * (2 ** max(0, failures - 1)))
        floor = min(self.base_backoff, ceiling)
        return self._uniform(floor, ceiling)
