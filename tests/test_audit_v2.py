"""V2 regression cases; execution is deferred to the deployment/CI environment."""

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from alembic import command
from alembic.config import Config
from app.ai_review import Options, evidence, request_review
from app.analysis import transition
from app.baseline import accumulate, backfill_batch, pseudonym
from app.db import Base, now
from app.investigation import capture
from app.models import (
    VPS,
    AIReport,
    BlockEvent,
    Event,
    HourlyBaseline,
    Identity,
    InvestigationSnapshot,
    Setting,
)
from app.schemas import ResultInput
from sqlalchemy import create_engine, delete, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from test_audit_analysis import observations, setup_probes


@pytest.fixture
def db(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "v2.db"))
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


@pytest.mark.parametrize("missing", ["outside", "controls", "heartbeat", "groups"])
def test_confirmation_requires_all_independent_evidence(db, missing):
    vps, target, probes = setup_probes(db)
    if missing == "outside":
        db.scalar(select(Identity).where(Identity.mainland.is_(False))).enabled = False
    elif missing == "controls":
        db.get(Setting, "control_targets").value = []
    elif missing == "heartbeat":
        vps.last_heartbeat_at = now() - timedelta(hours=1)
    else:
        for probe in probes:
            probe.independence_group = ""
    for probe in probes:
        observations(db, target, probe, False, now() - timedelta(minutes=3))
    transition(db, target.id)
    db.flush()
    incident = db.scalar(select(BlockEvent))
    assert incident.state == "suspected"
    assert incident.confidence < 0.5
    assert incident.evidence[-1]["missing_confirmation_evidence"]


def test_probe_timestamp_validation_preserves_datetime():
    stamp = now()
    result = ResultInput(target_id="x", started_at=stamp.isoformat(), success=True, control_ok=True)
    assert result.started_at == stamp


def incident_with_event(db):
    vps = VPS(name="vps")
    db.add(vps)
    db.flush()
    end = now().replace(second=0, microsecond=0)
    incident = BlockEvent(vps_id=vps.id, target_ip="8.8.8.8", state="manual",
                          window_start=end - timedelta(hours=1), window_end=end, first_known_bad_at=end)
    event = Event(vps_id=vps.id, bucket_start=end - timedelta(minutes=2), bucket_seconds=60,
                  first_seen=end - timedelta(minutes=2), last_seen=end - timedelta(minutes=2),
                  user_id=42, destination_domain="private.example", source_ip="1.2.3.4",
                  network="tcp", decision="accepted", connections=7)
    db.add_all([incident, event])
    db.flush()
    return incident, event


def test_snapshot_is_versioned_and_survives_expired_raw_rows(db):
    incident, event = incident_with_event(db)
    first = capture(db, incident.id)
    assert first.payload["windows"]["15"]["connections"] == 7
    assert capture(db, incident.id).id == first.id
    db.execute(delete(Event).where(Event.id == event.id))
    assert capture(db, incident.id).id == first.id
    incident.state = "recovered"
    incident.recovered_at = now()
    second = capture(db, incident.id)
    assert second.id != first.id
    assert first.payload["state"] == "manual"
    assert second.payload["windows"]["60"]["connections"] == 7
    assert db.scalar(select(func.count()).select_from(InvestigationSnapshot)) == 2


def test_hourly_backfill_has_transactional_checkpoint_and_pseudonyms(db):
    _, event = incident_with_event(db)
    db.add(Setting(key="baseline_backfill", value={"cursor": 0, "max_id": event.id}))
    db.flush()
    assert backfill_batch(db)
    db.commit()
    assert not backfill_batch(db)
    rows = db.scalars(select(HourlyBaseline)).all()
    assert len(rows) == 4
    assert {row.connections for row in rows} == {7}
    assert all(row.entity_hash not in ("42", "private.example", "1.2.3.4") for row in rows)
    raw = {column.name: getattr(event, column.name) for column in Event.__table__.columns}
    accumulate(db, [raw])
    db.rollback()
    assert db.scalar(select(HourlyBaseline.connections).where(
        HourlyBaseline.entity_hash == pseudonym("user", 42))) == 7


def test_ai_evidence_excludes_identifiers_and_free_text(db):
    incident, _ = incident_with_event(db)
    payload = capture(db, incident.id).payload
    payload["notes"] = "untrusted secret operator note"
    payload["correlations"] = [{"entity_type": "domain", "key": "private.example", "score": 12,
                                "connections": 7, "details": {"baseline_lift": 2}}]
    outgoing = json.dumps(evidence(payload))
    for private in ("private.example", "1.2.3.4", "8.8.8.8", "untrusted secret", incident.vps_id):
        assert private not in outgoing
    assert "C1" in outgoing and "W15" in outgoing


def test_ai_rejects_unknown_evidence_references(db):
    incident, _ = incident_with_event(db)
    payload = capture(db, incident.id).payload
    response = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps({
        "summary": "Review", "findings": [{"text": "Unsupported", "evidence_refs": ["FAKE"]}],
        "limitations": ["Uncertain"], "next_checks": []})}}]}
    with patch.dict("os.environ", {"AI_MODEL": "test", "AI_API_URL": "https://example.test/chat/completions", "AI_API_KEY": "test"}):
        with patch("app.ai_review.build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(response).encode()
            with pytest.raises(ValueError, match="unknown_evidence_reference"):
                request_review(payload, Options())


def test_upgrade_preserves_v1_rows_and_seeds_backfill(tmp_path):
    root = Path(__file__).resolve().parents[1]
    engine = create_engine("sqlite:///" + str(tmp_path / "upgrade.db"))
    config = Config(str(root / "audit-server/backend/alembic.ini"))
    config.set_main_option("script_location", str(root / "audit-server/backend/migrations"))
    with patch("app.db.engine", engine):
        command.upgrade(config, "0002")
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO vps (id,name,enabled,health,created_at) VALUES ('old','Old VPS',1,'{}',:stamp)"), {"stamp": now()})
            conn.execute(text("INSERT INTO audit_events_1m (id,vps_id,bucket_start,bucket_seconds,network,decision,connections,first_seen,last_seen) VALUES (17,'old',:stamp,60,'tcp','accepted',5,:stamp,:stamp)"), {"stamp": now()})
        command.upgrade(config, "head")
        command.upgrade(config, "head")
    with Session(engine) as session:
        assert session.get(VPS, "old").name == "Old VPS"
        assert session.get(Event, 17).connections == 5
        assert session.get(Setting, "baseline_backfill").value == {"cursor": 0, "max_id": 17}
    engine.dispose()


def test_ai_disabled_makes_no_request_and_daily_budget_is_enforced(db):
    from app.ai_review import run_once
    incident, _ = incident_with_event(db)
    snapshot = capture(db, incident.id)
    db.add(Setting(key="ai_daily_usage", value={"day": now().date().isoformat(), "requests": 1}))
    db.commit()
    factory = sessionmaker(db.bind, expire_on_commit=False)
    with patch("app.ai_review.Session", factory), patch("app.ai_review.configured", return_value=True):
        with patch("app.ai_review.request_review") as request:
            run_once()
            request.assert_not_called()
            db.add(Setting(key="ai_options", value={"enabled": True, "daily_request_limit": 1}))
            db.commit()
            run_once()
            request.assert_not_called()
    report = db.scalar(select(AIReport).where(AIReport.snapshot_id == snapshot.id))
    assert report.status == "pending"
