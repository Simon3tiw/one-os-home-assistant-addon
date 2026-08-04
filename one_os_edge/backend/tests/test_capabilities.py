import pytest
from one_os_addon.models import CapabilityEvidenceSnapshot
from one_os_addon.reconciliation import project_capability
from sqlalchemy import func, select


@pytest.mark.parametrize(
    ("evidence", "controllable"),
    [
        ({"domain": "climate", "supportedFeatures": 0, "min": 7, "max": 35, "step": 0.5}, False),
        ({"domain": "climate", "supportedFeatures": 1, "min": 35, "max": 7, "step": 0.5}, False),
        ({"domain": "climate", "supportedFeatures": "1", "min": 7, "max": 35, "step": 0.5}, False),
        (
            {"domain": "button", "supportedFeatures": 0, "min": None, "max": None, "step": None},
            False,
        ),
    ],
)
def test_ambiguous_or_high_risk_evidence_never_expands_control(evidence, controllable):
    capability = project_capability(evidence)
    assert capability["technicallyControllable"] is controllable
    assert capability["actions"] == []


def test_valid_climate_evidence_projects_bounded_temperature_action():
    capability = project_capability(
        {"domain": "climate", "supportedFeatures": 1, "min": 7, "max": 35, "step": 0.5}
    )
    assert capability["actions"] == ["set_temperature"]
    assert capability["constraints"]["set_temperature"] == {
        "minimum": 7,
        "maximum": 35,
        "step": 0.5,
    }
    assert capability["adapterVersion"] == "ha-2025.1-v2"


def test_evidence_history_is_append_only_across_drift(client, auth, fake_ha):
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    point = next(
        item
        for item in client.get("/api/v1/inventory", headers=auth).json()["flatPoints"]
        if item["source"]["registryId"] == "light.office"
    )
    with client.app.state.session() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(CapabilityEvidenceSnapshot)
                .where(CapabilityEvidenceSnapshot.point_id == point["id"])
            )
            == 1
        )

    fake_ha.states["light.office"]["attributes"]["supported_features"] = 1
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    with client.app.state.session() as session:
        snapshots = session.scalars(
            select(CapabilityEvidenceSnapshot)
            .where(CapabilityEvidenceSnapshot.point_id == point["id"])
            .order_by(CapabilityEvidenceSnapshot.captured_at)
        ).all()
        assert len(snapshots) == 2
        assert snapshots[0].evidence_hash != snapshots[1].evidence_hash
        assert {snapshot.adapter_version for snapshot in snapshots} == {"ha-2025.1-v2"}
