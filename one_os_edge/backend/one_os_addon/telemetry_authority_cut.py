from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime
from typing import Any

from sqlalchemy import select, text

from .models import (
    EdgeIdentity,
    TelemetryAuthorityCut,
    TelemetryBatch,
    TelemetryBatchGap,
    TelemetryBatchRecord,
    TelemetryJournalState,
)
from .telemetry_contract_v2 import parse_backlog_manifest, parse_historical_receipt


class TelemetryAuthorityCutRepository:
    """The sole transactional writer for durable telemetry-authority cuts."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    @staticmethod
    def _begin(session) -> str:
        dialect = session.get_bind().dialect.name
        if dialect == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))
        return dialect

    @staticmethod
    def _locked(statement, dialect: str):
        return statement.with_for_update() if dialect == "postgresql" else statement

    @staticmethod
    def _b64digest(value: bytes) -> str:
        return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()

    def _locked_authority(self, session, dialect: str, cut_journal_max_id: int):
        identity = session.scalar(
            self._locked(select(EdgeIdentity).where(EdgeIdentity.id == 1), dialect)
        )
        journal = session.scalar(
            self._locked(
                select(TelemetryJournalState).where(TelemetryJournalState.id == 1), dialect
            )
        )
        batches = session.scalars(
            self._locked(
                select(TelemetryBatch)
                .where(TelemetryBatch.journal_id <= cut_journal_max_id)
                .order_by(TelemetryBatch.journal_id),
                dialect,
            )
        ).all()
        return identity, journal, batches

    @staticmethod
    def _batch_entries(batches: list[TelemetryBatch]) -> list[dict[str, Any]]:
        return [
            {
                "batchAuthorizationRevision": batch.batch_authorization_revision,
                "batchId": batch.batch_id,
                "credentialId": batch.credential_id,
                "journalId": batch.journal_id,
                "requestLength": len(batch.request_bytes),
                "requestSha256": batch.request_sha256,
            }
            for batch in batches
        ]

    def _validate_manifest_relation(
        self,
        manifest: dict[str, Any],
        *,
        cut_marker_id: str,
        renewal_request_id: str,
        cut_journal_max_id: int,
        identity: EdgeIdentity,
        journal: TelemetryJournalState,
        batches: list[TelemetryBatch],
    ) -> None:
        batch_by_id = {batch.batch_id: batch for batch in batches}
        manifest_batch_ids = [entry["batchId"] for entry in manifest["entries"]]
        selected_batches = [batch_by_id.get(batch_id) for batch_id in manifest_batch_ids]
        entries = self._batch_entries([batch for batch in selected_batches if batch is not None])
        if (
            len(entries) != len(manifest_batch_ids)
            or cut_journal_max_id > journal.last_journal_id
            or manifest["cutMarkerId"] != cut_marker_id
            or manifest["renewalOperationId"] != renewal_request_id
            or manifest["installationId"] != identity.installation_id
            or manifest["lineageId"] != identity.lineage_id
            or manifest["batchAuthorizationRevision"] != identity.telemetry_authorization_revision
            or manifest["cutJournalMaxId"] != cut_journal_max_id
            or manifest["entries"] != entries
        ):
            raise ValueError("manifest_relation_conflict")

    @staticmethod
    def _validate_receipt_relation(
        receipt: dict[str, Any],
        manifest: dict[str, Any],
        row: TelemetryAuthorityCut,
    ) -> None:
        aliases = (
            ("renewalOperationId", row.renewal_request_id),
            ("installationId", row.installation_id),
            ("lineageId", row.lineage_id),
            ("cutMarkerId", row.cut_marker_id),
            ("cutJournalMaxId", row.cut_journal_max_id),
            ("historicalAuthorizationRevision", row.historical_authorization_revision),
            ("ingestAuthorizationRevision", row.ingest_authorization_revision),
            ("entryCount", manifest["entryCount"]),
            ("totalRequestBytes", manifest["totalRequestBytes"]),
            ("entries", manifest["entries"]),
        )
        manifest_hash = TelemetryAuthorityCutRepository._b64digest(row.manifest_bytes)
        if (
            any(receipt[name] != expected for name, expected in aliases)
            or not hmac.compare_digest(receipt["backlogManifestSha256"], manifest_hash)
            or manifest["cutJournalMaxId"] != row.cut_journal_max_id
        ):
            raise ValueError("receipt_relation_conflict")

    def open(
        self,
        cut_marker_id: str,
        renewal_request_id: str,
        manifest: bytes | dict[str, Any],
        cut_journal_max_id: int,
        at: datetime,
    ) -> None:
        manifest_document, manifest_bytes = parse_backlog_manifest(manifest)
        if type(cut_journal_max_id) is not int:
            raise ValueError("cut_authority_conflict")
        with self._session_factory() as session:
            dialect = self._begin(session)
            identity, journal, batches = self._locked_authority(
                session, dialect, cut_journal_max_id
            )
            if identity is None or journal is None:
                raise ValueError("cut_authority_conflict")
            if not 0 <= cut_journal_max_id <= journal.last_journal_id:
                raise ValueError("cut_journal_conflict")
            manifest_batch_ids = {entry["batchId"] for entry in manifest_document["entries"]}
            unacked_batch_ids = {batch.batch_id for batch in batches if batch.status != "acked"}
            if manifest_batch_ids != unacked_batch_ids:
                raise ValueError("manifest_relation_conflict")
            if identity.telemetry_authorization_revision >= 9_223_372_036_854_775_807:
                raise ValueError("cut_authority_saturated")
            self._validate_manifest_relation(
                manifest_document,
                cut_marker_id=cut_marker_id,
                renewal_request_id=renewal_request_id,
                cut_journal_max_id=cut_journal_max_id,
                identity=identity,
                journal=journal,
                batches=batches,
            )
            session.add(
                TelemetryAuthorityCut(
                    cut_marker_id=cut_marker_id,
                    renewal_request_id=renewal_request_id,
                    installation_id=identity.installation_id,
                    lineage_id=identity.lineage_id,
                    historical_authorization_revision=identity.telemetry_authorization_revision,
                    ingest_authorization_revision=identity.telemetry_authorization_revision + 1,
                    cut_journal_max_id=cut_journal_max_id,
                    backlog_mode="none" if cut_journal_max_id == 0 else "historical",
                    manifest_bytes=manifest_bytes,
                    manifest_sha256=hashlib.sha256(manifest_bytes).digest(),
                    receipt_bytes=None,
                    receipt_sha256=None,
                    milestone="cut_open",
                    cut_opened_at=at,
                )
            )
            session.commit()

    def _transition(self, cut_marker_id: str, expected: str, at: datetime, **values) -> None:
        with self._session_factory() as session:
            dialect = self._begin(session)
            row = session.scalar(
                self._locked(
                    select(TelemetryAuthorityCut).where(
                        TelemetryAuthorityCut.cut_marker_id == cut_marker_id
                    ),
                    dialect,
                )
            )
            if row is None or row.milestone != expected:
                raise ValueError("cut_transition_conflict")
            for name, value in values.items():
                setattr(row, name, value)
            session.commit()

    def store_receipt(
        self, cut_marker_id: str, receipt: bytes | dict[str, Any], at: datetime
    ) -> None:
        receipt_document, receipt_bytes = parse_historical_receipt(receipt)
        with self._session_factory() as session:
            dialect = self._begin(session)
            row = session.scalar(
                self._locked(
                    select(TelemetryAuthorityCut).where(
                        TelemetryAuthorityCut.cut_marker_id == cut_marker_id
                    ),
                    dialect,
                )
            )
            if row is None or row.milestone != "cut_open":
                raise ValueError("cut_transition_conflict")
            manifest, exact_manifest_bytes = parse_backlog_manifest(row.manifest_bytes)
            if not hmac.compare_digest(exact_manifest_bytes, row.manifest_bytes):
                raise ValueError("manifest_relation_conflict")
            identity, journal, batches = self._locked_authority(
                session, dialect, row.cut_journal_max_id
            )
            if identity is None or journal is None:
                raise ValueError("cut_authority_conflict")
            self._validate_manifest_relation(
                manifest,
                cut_marker_id=row.cut_marker_id,
                renewal_request_id=row.renewal_request_id,
                cut_journal_max_id=row.cut_journal_max_id,
                identity=identity,
                journal=journal,
                batches=batches,
            )
            self._validate_receipt_relation(receipt_document, manifest, row)
            row.receipt_bytes = receipt_bytes
            row.receipt_sha256 = hashlib.sha256(receipt_bytes).digest()
            row.receipt_stored_at = at
            row.milestone = "receipt_stored"
            session.commit()

    def promote_identity(self, cut_marker_id: str, at: datetime) -> None:
        with self._session_factory() as session:
            dialect = self._begin(session)
            row = session.scalar(
                self._locked(
                    select(TelemetryAuthorityCut).where(
                        TelemetryAuthorityCut.cut_marker_id == cut_marker_id
                    ),
                    dialect,
                )
            )
            if row is None or row.milestone != "receipt_stored" or row.receipt_bytes is None:
                raise ValueError("cut_transition_conflict")
            manifest, _ = parse_backlog_manifest(row.manifest_bytes)
            receipt, _ = parse_historical_receipt(row.receipt_bytes)
            identity, journal, batches = self._locked_authority(
                session, dialect, row.cut_journal_max_id
            )
            if identity is None or journal is None:
                raise ValueError("cut_authority_conflict")
            self._validate_manifest_relation(
                manifest,
                cut_marker_id=row.cut_marker_id,
                renewal_request_id=row.renewal_request_id,
                cut_journal_max_id=row.cut_journal_max_id,
                identity=identity,
                journal=journal,
                batches=batches,
            )
            self._validate_receipt_relation(receipt, manifest, row)
            if identity.telemetry_authorization_revision != row.historical_authorization_revision:
                raise ValueError("cut_authority_conflict")
            if row.backlog_mode == "historical":
                batch_ids = [entry["batchId"] for entry in receipt["entries"]]
                remaining_records = session.scalar(
                    select(TelemetryBatchRecord)
                    .where(TelemetryBatchRecord.batch_id.in_(batch_ids))
                    .limit(1)
                )
                remaining_gaps = session.scalar(
                    select(TelemetryBatchGap)
                    .where(TelemetryBatchGap.batch_id.in_(batch_ids))
                    .limit(1)
                )
                if (
                    any(batch.status != "acked" for batch in batches)
                    or remaining_records is not None
                    or remaining_gaps is not None
                ):
                    raise ValueError("historical_backlog_not_drained")
            identity.telemetry_authorization_revision = row.ingest_authorization_revision
            row.identity_promoted_at = at
            row.milestone = "identity_promoted"
            session.commit()

    def mark_backlog_drained(self, cut_marker_id: str, at: datetime) -> None:
        self._transition(
            cut_marker_id,
            "identity_promoted",
            at,
            backlog_drained_at=at,
            milestone="backlog_drained",
        )

    def finish(self, cut_marker_id: str, at: datetime) -> None:
        with self._session_factory() as session:
            dialect = self._begin(session)
            row = session.scalar(
                self._locked(
                    select(TelemetryAuthorityCut).where(
                        TelemetryAuthorityCut.cut_marker_id == cut_marker_id
                    ),
                    dialect,
                )
            )
            expected = (
                "identity_promoted"
                if row is not None and row.backlog_mode == "none"
                else "backlog_drained"
            )
            if row is None or row.milestone != expected:
                raise ValueError("cut_transition_conflict")
            row.terminal_at = at
            row.milestone = "terminal"
            session.commit()
