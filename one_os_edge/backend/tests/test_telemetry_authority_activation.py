from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from one_os_addon.app import create_app
from one_os_addon.models import EdgeIdentity, TelemetryAuthorityActivation
from one_os_addon.telemetry_authority import (
    PINNED_SCHEMA_HASHES,
    TelemetryAuthorityError,
    TelemetryAuthorityManager,
    build_enable_preimage,
)

CONTRACT = Path(__file__).resolve().parents[3] / "docs/reference/contracts/telemetry/v2"
VECTORS = CONTRACT / "one-os-phase2c-p-canonical-vectors-v2-draft4-20260825.json"
INSTALLATION_ID = "00000000-0000-4000-8000-000000000002"
CREDENTIAL_ID = "00000000-0000-4000-8000-000000002222"
CERTIFICATE_SHA256 = "s5-H8FWELCE6O7LgjcBTbUc6RyjNQp33u6Vk4NKCvv8"


def _vectors():
    return json.loads(VECTORS.read_text())


def _digest(raw: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()


def _app(tmp_path):
    app = create_app(database_url=f"sqlite:///{tmp_path / 'authority.db'}", pairing_backend=False)
    with app.state.session() as session:
        identity = session.get(EdgeIdentity, 1)
        identity.installation_id = INSTALLATION_ID
        identity.lineage_id = INSTALLATION_ID
        identity.status = "paired"
        identity.credential_id = CREDENTIAL_ID
        identity.certificate_sha256 = CERTIFICATE_SHA256
        identity.telemetry_authorization_revision = 7
        session.commit()
    return app


class _Client:
    def __init__(self, capability: bytes, response: bytes):
        self.capability_bytes = capability
        self.response_bytes = response
        self.enable_requests: list[bytes] = []

    def get_capability(self, _certificate: str, _private_key: str) -> bytes:
        return self.capability_bytes

    def enable(self, request: bytes, _certificate: str, _private_key: str) -> bytes:
        self.enable_requests.append(request)
        return self.response_bytes


def _identity():
    return {
        "status": "paired",
        "installationId": INSTALLATION_ID,
        "credentialId": CREDENTIAL_ID,
        "certificateSha256": CERTIFICATE_SHA256,
        "certificatePem": "certificate",
        "privateKeyPem": "private-key",
        "revision": 7,
    }


def test_schema_pins_are_exact_accepted_file_hashes() -> None:
    expected = {
        "telemetryBatchSchemaSha256": (
            "one-os-phase2c-p-telemetry-batch-v2-draft4-20260825.schema.json"
        ),
        "telemetryAckSchemaSha256": "one-os-phase2c-p-telemetry-ack-v2-draft4-20260825.schema.json",
        "telemetryErrorSchemaSha256": (
            "one-os-phase2c-p-telemetry-error-v2-draft4-20260825.schema.json"
        ),
        "renewalControlSchemaSha256": (
            "one-os-phase2c-p-renewal-control-v2-draft4-20260825.schema.json"
        ),
    }
    assert PINNED_SCHEMA_HASHES == {
        key: _digest((CONTRACT / name).read_bytes()) for key, name in expected.items()
    }


def test_activation_persists_exact_capability_enable_request_and_response(tmp_path) -> None:
    vectors = _vectors()
    capability = vectors["capability"]["canonicalUtf8"].encode()
    response = vectors["enableResponse"]["canonicalUtf8"].encode()
    client = _Client(capability, response)
    signed_preimages = []

    def signer(preimage: bytes) -> bytes:
        signed_preimages.append(preimage)
        return b"s" * 64

    app = _app(tmp_path)
    manager = TelemetryAuthorityManager(
        app.state.session,
        client,
        _identity,
        signer,
        uuid_factory=lambda: vectors["enableRequest"]["object"]["requestId"],
        nonce_factory=lambda: base64.urlsafe_b64decode(
            vectors["enableRequest"]["object"]["edgeNonce"] + "="
        ),
        clock=lambda: datetime(2030, 1, 1, 12, 0, 30, tzinfo=UTC),
    )

    assert manager.activate() == response
    request = client.enable_requests[0]
    request_document = json.loads(request)
    assert signed_preimages == [
        build_enable_preimage({k: v for k, v in request_document.items() if k != "signature"})
    ]
    assert (
        request_document["signature"] == base64.urlsafe_b64encode(b"s" * 64).rstrip(b"=").decode()
    )

    with app.state.session() as session:
        row = session.get(TelemetryAuthorityActivation, 1)
        assert row.capability_bytes == capability
        assert row.capability_sha256 == hashlib.sha256(capability).digest()
        assert row.server_nonce == base64.urlsafe_b64decode(
            vectors["capability"]["object"]["serverNonce"] + "="
        )
        assert row.enable_request_bytes == request
        assert row.enable_response_bytes == response
        assert row.status == "enabled"
        assert row.installation_id == INSTALLATION_ID
        assert row.credential_id == CREDENTIAL_ID
        assert row.certificate_sha256 == CERTIFICATE_SHA256
        assert row.telemetry_authorization_revision == 7
    assert manager.enabled_revision() == 7


def test_activation_is_default_off_and_conflicting_or_expired_capability_is_fail_closed(
    tmp_path,
) -> None:
    vectors = _vectors()
    app = _app(tmp_path)
    client = _Client(
        vectors["capability"]["canonicalUtf8"].encode(),
        vectors["enableResponse"]["canonicalUtf8"].encode(),
    )
    manager = TelemetryAuthorityManager(
        app.state.session,
        client,
        _identity,
        lambda _: b"s" * 64,
        uuid_factory=lambda: vectors["enableRequest"]["object"]["requestId"],
        nonce_factory=lambda: b"z" * 32,
        clock=lambda: datetime(2030, 1, 1, 12, 5, tzinfo=UTC),
    )
    assert manager.enabled_revision() is None
    with pytest.raises(TelemetryAuthorityError, match="capability_not_current"):
        manager.activate()
    assert client.enable_requests == []


def test_durable_enabled_response_must_still_bind_current_identity(tmp_path) -> None:
    vectors = _vectors()
    app = _app(tmp_path)
    manager = TelemetryAuthorityManager(
        app.state.session,
        _Client(
            vectors["capability"]["canonicalUtf8"].encode(),
            vectors["enableResponse"]["canonicalUtf8"].encode(),
        ),
        _identity,
        lambda _: b"s" * 64,
        uuid_factory=lambda: vectors["enableRequest"]["object"]["requestId"],
        nonce_factory=lambda: b"z" * 32,
        clock=lambda: datetime(2030, 1, 1, 12, 0, 30, tzinfo=UTC),
    )
    manager.activate()
    with app.state.session() as session:
        session.get(EdgeIdentity, 1).telemetry_authorization_revision = 8
        session.commit()
    with pytest.raises(TelemetryAuthorityError, match="durable_activation_conflict"):
        manager.enabled_revision()


def test_response_loss_replays_exact_durable_request_after_capability_expiry(tmp_path) -> None:
    from datetime import timedelta

    vectors = _vectors()
    app = _app(tmp_path)

    class ResponseLossClient(_Client):
        def enable(self, request, certificate, private_key):
            self.enable_requests.append(request)
            if len(self.enable_requests) == 1:
                raise ConnectionError("response lost")
            return self.response_bytes

    client = ResponseLossClient(
        vectors["capability"]["canonicalUtf8"].encode(),
        vectors["enableResponse"]["canonicalUtf8"].encode(),
    )
    now = [datetime(2030, 1, 1, 12, 0, 30, tzinfo=UTC)]
    manager = TelemetryAuthorityManager(
        app.state.session,
        client,
        _identity,
        lambda _: b"s" * 64,
        uuid_factory=lambda: vectors["enableRequest"]["object"]["requestId"],
        nonce_factory=lambda: b"z" * 32,
        clock=lambda: now[0],
    )
    with pytest.raises(ConnectionError, match="response lost"):
        manager.activate()
    now[0] += timedelta(minutes=10)
    assert manager.activate() == client.response_bytes
    assert client.enable_requests[0] == client.enable_requests[1]


@pytest.mark.parametrize("artifact", ("request", "response", "enabled_at"))
def test_enabled_revision_rejects_tampered_durable_artifacts(tmp_path, artifact: str) -> None:
    from datetime import timedelta

    vectors = _vectors()
    app = _app(tmp_path)
    manager = TelemetryAuthorityManager(
        app.state.session,
        _Client(
            vectors["capability"]["canonicalUtf8"].encode(),
            vectors["enableResponse"]["canonicalUtf8"].encode(),
        ),
        _identity,
        lambda _: b"s" * 64,
        uuid_factory=lambda: vectors["enableRequest"]["object"]["requestId"],
        nonce_factory=lambda: b"z" * 32,
        clock=lambda: datetime(2030, 1, 1, 12, 0, 30, tzinfo=UTC),
    )
    manager.activate()
    with app.state.session() as session:
        row = session.get(TelemetryAuthorityActivation, 1)
        if artifact == "request":
            row.enable_request_bytes += b" "
        elif artifact == "response":
            row.enable_response_bytes = row.enable_response_bytes.replace(
                b"12:00:30Z", b"12:00:31Z"
            )
        else:
            row.enabled_at += timedelta(seconds=1)
        session.commit()
    with pytest.raises(TelemetryAuthorityError, match="durable_activation_conflict"):
        manager.enabled_revision()


def test_postgresql_activation_lock_sql_has_for_update_and_no_begin_immediate() -> None:
    from one_os_addon.telemetry_authority import _activation_lock_statements
    from sqlalchemy.dialects import postgresql

    sql = "\n".join(
        str(s.compile(dialect=postgresql.dialect()))
        for s in _activation_lock_statements("postgresql")
    )
    assert "FOR UPDATE" in sql
    assert "BEGIN IMMEDIATE" not in sql
