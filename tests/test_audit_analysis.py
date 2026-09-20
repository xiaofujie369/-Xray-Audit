from datetime import timedelta
from unittest.mock import Mock, patch

import pytest
from alembic import command
from alembic.config import Config
from app.analysis import calculate_score, correlate, transition
from app.db import Base, now
from app.models import VPS, BlockEvent, Correlation, Event, Identity, ProbeResult, Target
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from probe.probe_agent import check


@pytest.fixture
def db(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "analysis.db"))
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


def setup_probes(db):
    vps = VPS(name="vps")
    db.add(vps)
    db.flush()
    target = Target(vps_id=vps.id, address="8.8.8.8", port=443)
    db.add(target)
    probes = [
        Identity(name=f"cn-{i}", kind="probes", mainland=True, independence_group=str(i), token_hash=str(i))
        for i in range(2)
    ]
    db.add_all(probes)
    db.commit()
    return vps, target, probes


def observations(db, target, probe, success, start, control=True, error="timeout"):
    for i in range(2):
        db.add(
            ProbeResult(
                probe_id=probe.id,
                target_id=target.id,
                success=success,
                control_ok=control,
                started_at=start + timedelta(seconds=i * 30),
                error_class=None if success else error,
            )
        )
    db.commit()


def test_consensus_recovery_and_control_exclusion(db):
    vps, target, probes = setup_probes(db)
    stamp = now() - timedelta(minutes=5)
    observations(db, target, probes[0], False, stamp)
    transition(db, target.id)
    db.commit()
    incident = db.scalar(select(BlockEvent))
    assert incident.state == "suspected"
    observations(db, target, probes[1], False, stamp, control=False)
    transition(db, target.id)
    assert incident.state == "suspected"
    observations(db, target, probes[1], False, stamp + timedelta(minutes=1))
    transition(db, target.id)
    db.commit()
    assert incident.state == "confirmed"
    assert incident.probe_count == 2
    assert (incident.window_end - incident.window_start).total_seconds() == 3600
    for probe in probes:
        observations(db, target, probe, True, stamp + timedelta(minutes=3))
    transition(db, target.id)
    assert incident.state == "recovered"


def test_same_network_is_not_independent_and_refusal_is_not_block(db):
    _, target, probes = setup_probes(db)
    probes[1].independence_group = probes[0].independence_group
    for probe in probes:
        observations(db, target, probe, False, now() - timedelta(minutes=3))
    transition(db, target.id)
    db.commit()
    assert db.scalar(select(BlockEvent)).state == "suspected"
    assert db.scalar(select(BlockEvent)).probe_count == 1


def test_popular_baseline_suppression():
    weights = [0.3, 0.25, 0.2, 0.15, 0.1]
    assert calculate_score(1, 1, 1, 5, 0.9, weights) == 0
    assert calculate_score(1, 8, 1, 5, 0.9, weights) > 80
    assert calculate_score(1, 8, 1, 5, 0.9, weights) > calculate_score(0.2, 8, 0.1, 1, 0.1, weights)


def test_correlation_insufficient_baseline_and_recalculation(db):
    vps, target, _ = setup_probes(db)
    end = now().replace(second=0, microsecond=0)
    incident = BlockEvent(
        vps_id=vps.id,
        target_id=target.id,
        target_ip=target.address,
        state="confirmed",
        window_start=end - timedelta(hours=1),
        window_end=end,
        first_known_bad_at=end,
    )
    db.add(incident)
    db.add(
        Event(
            vps_id=vps.id,
            bucket_start=end - timedelta(minutes=2),
            bucket_seconds=60,
            user_id=7,
            source_ip="1.2.3.4",
            destination_domain="example.com",
            destination_ip=None,
            destination_port=443,
            connections=10,
            network="tcp",
            decision="accepted",
            first_seen=end - timedelta(minutes=2),
            last_seen=end - timedelta(minutes=2),
        )
    )
    db.commit()
    correlate(db, incident.id)
    db.commit()
    rows = db.scalars(select(Correlation)).all()
    assert len(rows) == 3
    assert all(row.details["insufficient_baseline"] and row.score == 0 for row in rows)
    correlate(db, incident.id)
    db.commit()
    assert len(db.scalars(select(Correlation)).all()) == 3


def test_probe_success_timeout_refusal():
    target = {"id": "target", "address": "8.8.8.8", "port": 443, "protocol": "tcp"}
    with patch("probe.probe_agent.socket.create_connection", return_value=Mock()):
        assert check(target)["success"]
    with patch("probe.probe_agent.socket.create_connection", side_effect=TimeoutError):
        assert check(target)["error_class"] == "timeout"
    import errno

    with patch(
        "probe.probe_agent.socket.create_connection", side_effect=OSError(errno.ECONNREFUSED, "refused")
    ):
        assert check(target)["error_class"] == "connection_refused"


def test_migration_empty_upgrade_and_repeat(tmp_path):
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    engine = create_engine("sqlite:///" + str(tmp_path / "migrations.db"))
    config = Config(str(root / "audit-server/backend/alembic.ini"))
    config.set_main_option("script_location", str(root / "audit-server/backend/migrations"))
    with patch("app.db.engine", engine):
        command.upgrade(config, "head")
        command.upgrade(config, "head")
    from sqlalchemy import inspect

    assert set(Base.metadata.tables) <= set(inspect(engine).get_table_names())
    engine.dispose()
