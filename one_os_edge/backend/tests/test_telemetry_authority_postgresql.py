import os
import threading
import time

import pytest
from one_os_addon.models import EdgeIdentity, TelemetryJournalState
from one_os_addon.telemetry_authority import (
    _activation_lock_statements,
)
from one_os_addon.telemetry_authority import (
    _begin_write as _begin_activation_write,
)
from one_os_addon.telemetry_delivery import (
    _begin_write as _begin_delivery_write,
)
from one_os_addon.telemetry_delivery import (
    _locked,
)
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

POSTGRES_URL = os.getenv("ONE_OS_EDGE_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="requires an explicit disposable PostgreSQL database",
)


def _run_workers(worker):
    barrier = threading.Barrier(2)
    results = []
    errors = []

    def run(index):
        try:
            barrier.wait(timeout=5)
            results.append(worker(index))
        except BaseException as error:  # captured and asserted in parent thread
            errors.append(error)

    threads = [threading.Thread(target=run, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    return results


def test_postgresql_activation_and_journal_locks_prevent_lost_updates() -> None:
    engine = create_engine(POSTGRES_URL)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with engine.begin() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0021"
        connection.execute(text("UPDATE edge_identity SET revision = 0 WHERE id = 1"))
        connection.execute(text("DELETE FROM telemetry_journal_state"))
        connection.execute(
            text("INSERT INTO telemetry_journal_state(id, last_journal_id) VALUES (1, 0)")
        )

    def activation_worker(index):
        with sessions() as session:
            dialect = _begin_activation_write(session)
            for statement in _activation_lock_statements(dialect):
                session.execute(statement)
            identity = session.get(EdgeIdentity, 1)
            before = identity.revision
            if index == 0:
                time.sleep(0.15)
            identity.revision = before + 1
            session.commit()
            return before

    assert sorted(_run_workers(activation_worker)) == [0, 1]
    with sessions() as session:
        assert session.get(EdgeIdentity, 1).revision == 2

    def journal_worker(index):
        with sessions() as session:
            dialect = _begin_delivery_write(session)
            state = session.scalar(
                _locked(
                    select(TelemetryJournalState).where(TelemetryJournalState.id == 1),
                    dialect,
                )
            )
            before = state.last_journal_id
            if index == 0:
                time.sleep(0.15)
            state.last_journal_id = before + 1
            session.commit()
            return before + 1

    assert sorted(_run_workers(journal_worker)) == [1, 2]
    with sessions() as session:
        assert session.get(TelemetryJournalState, 1).last_journal_id == 2
    engine.dispose()
