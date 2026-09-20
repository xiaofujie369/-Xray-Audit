"""Reachability evidence and explainable association, never causal attribution."""

import math
from datetime import timedelta

from sqlalchemy import String, cast, delete, func, or_, select

from .db import now, utc
from .models import BlockEvent, Correlation, Event, Identity, Job, ProbeResult, Target
from .settings import settings


def transition(db, target_id):
    # A per-target row lock serializes concurrent probe workers.
    target = db.scalar(select(Target).where(Target.id == target_id).with_for_update())
    if target is None or not target.enabled:
        return
    config = settings(db)
    cutoff = now() - timedelta(
        seconds=config["probe_interval_seconds"]
        * (max(config["fail_consecutive"], config["recover_consecutive"]) + 2)
    )
    probes = db.scalars(
        select(Identity).where(
            Identity.kind == "probes", Identity.enabled.is_(True), Identity.mainland.is_(True)
        )
    ).all()
    bad, good, evidence, bad_times, good_times = set(), set(), [], [], []
    for probe in probes:
        rows = db.scalars(
            select(ProbeResult)
            .where(
                ProbeResult.probe_id == probe.id,
                ProbeResult.target_id == target_id,
                ProbeResult.started_at >= cutoff,
            )
            .order_by(ProbeResult.started_at.desc())
            .limit(max(config["fail_consecutive"], config["recover_consecutive"]) + 2)
        ).all()
        if not rows:
            continue
        group = probe.independence_group or probe.id
        evidence.append(
            {
                "probe": probe.name,
                "group": group,
                "results": [
                    dict(
                        time=utc(row.started_at).isoformat(),
                        success=row.success,
                        control_ok=row.control_ok,
                        error=row.error_class,
                        latency_ms=row.latency_ms,
                    )
                    for row in rows
                ],
            }
        )
        failures = []
        successes = []
        for row in rows:
            if not row.control_ok or row.success or row.error_class not in ("timeout", "network_unreachable"):
                break
            failures.append(row)
        for row in rows:
            if not row.control_ok or not row.success:
                break
            successes.append(row)
        if len(failures) >= config["fail_consecutive"]:
            bad.add(group)
            bad_times.append(min(utc(r.started_at) for r in failures))
        if len(successes) >= config["recover_consecutive"]:
            good.add(group)
        good_times.extend(utc(r.started_at) for r in rows if r.success and r.control_ok)
    # Conflicting observations from one network cannot count as independent agreement.
    conflicting = bad & good
    bad -= conflicting
    good -= conflicting
    active = db.scalar(
        select(BlockEvent)
        .where(BlockEvent.target_id == target_id, BlockEvent.state.in_(["suspected", "confirmed"]))
        .order_by(BlockEvent.detected_at.desc())
        .limit(1)
    )
    state = "confirmed" if len(bad) >= config["min_distinct_probes"] else "suspected" if bad else None
    if active and not bad and len(good) >= config["min_distinct_probes"]:
        state = "recovered" if active.state == "confirmed" else "false_positive"
    if state is None:
        return
    previous = active.state if active else None
    if active is None:
        first_bad = min(bad_times)
        last_good = db.scalar(
            select(func.max(ProbeResult.started_at)).where(
                ProbeResult.target_id == target_id,
                ProbeResult.success.is_(True),
                ProbeResult.control_ok.is_(True),
                ProbeResult.started_at < first_bad,
            )
        )
        active = BlockEvent(
            vps_id=target.vps_id,
            target_id=target.id,
            target_ip=target.address,
            target_port=target.port,
            state=state,
            first_known_bad_at=first_bad,
            last_known_good_at=last_good,
            window_end=first_bad,
            window_start=first_bad - timedelta(minutes=config["lookback_minutes"]),
        )
        db.add(active)
        db.flush()
    elif active.state == "confirmed" and state == "suspected":
        state = "confirmed"
    active.state = state
    count = len(good) if state in ("recovered", "false_positive") else len(bad)
    active.probe_count = count
    active.confidence = min(1, count / max(2, config["min_distinct_probes"]))
    if state in ("recovered", "false_positive"):
        active.recovered_at = now()
    if previous != state:
        active.evidence = list(active.evidence or []) + [
            {
                "state": state,
                "time": now().isoformat(),
                "observations": evidence,
                "single_network": count < 2,
                "control_targets_configured": bool(config["control_targets"]),
            }
        ]
        if state == "confirmed" and bad_times:
            active.first_known_bad_at = min(utc(active.first_known_bad_at), min(bad_times))
            active.window_end = active.first_known_bad_at
            active.window_start = active.window_end - timedelta(minutes=config["lookback_minutes"])
        db.add(Job(kind="notify", payload={"event": state, "vps_id": target.vps_id, "incident": active.id}))
        if state == "confirmed":
            db.add(Job(kind="correlate", payload={"id": active.id}))


ENTITIES = {
    "user": Event.user_id,
    "source_ip": Event.source_ip,
    "domain": Event.destination_domain,
    "destination_ip": Event.destination_ip,
    "node": Event.node_id,
}


def calculate_score(presence, lift, proximity, cross_vps, share, weights):
    components = [
        presence,
        min(1, max(0, math.log2(max(1, lift)) / 4)),
        proximity,
        min(1, max(0, cross_vps - 1) / 4),
        share,
    ]
    # Baseline suppression applies to the complete score, not only its lift term.
    suppression = min(1, max(0, (lift - 1) / 3))
    return round(100 * sum(w * max(0, min(1, v)) for w, v in zip(weights, components)) * suppression, 2)


def correlate(db, event_id):
    incident = db.scalar(select(BlockEvent).where(BlockEvent.id == event_id).with_for_update())
    if incident is None:
        return
    config = settings(db)
    start, end = utc(incident.window_start), utc(incident.window_end)
    duration = (end - start).total_seconds()
    window = [Event.vps_id == incident.vps_id, Event.bucket_start >= start, Event.bucket_start < end]
    if db.scalar(select(Event.id).where(*window).limit(1)) is None and db.scalar(
        select(Correlation.id).where(Correlation.block_event_id == event_id).limit(1)
    ):
        # Preserve the historical snapshot after detailed source retention expires.
        return
    # Control windows exclude every incident window, including suspected incidents.
    previous = db.scalars(
        select(BlockEvent).where(
            BlockEvent.vps_id == incident.vps_id,
            BlockEvent.window_end >= start - timedelta(days=8),
            BlockEvent.window_start < start,
        )
    ).all()
    controls = []
    for days in range(1, 8):
        a, b = start - timedelta(days=days), end - timedelta(days=days)
        if not any(utc(e.window_start) < b and utc(e.window_end) > a for e in previous):
            exists = db.scalar(
                select(Event.id)
                .where(Event.vps_id == incident.vps_id, Event.bucket_start >= a, Event.bucket_start < b)
                .limit(1)
            )
            if exists:
                controls.append((a, b))
    method = "same_hour_previous_7_days"
    if len(controls) < 2:
        method = "previous_24h_excluding_incidents"
        controls = []
        for hour in range(24):
            a = start - timedelta(hours=hour + 1)
            b = a + timedelta(hours=1)
            if not any(utc(e.window_start) < b and utc(e.window_end) > a for e in previous):
                controls.append((a, b))
    baseline = (
        [
            Event.vps_id == incident.vps_id,
            or_(*((Event.bucket_start >= a) & (Event.bucket_start < b) for a, b in controls)),
        ]
        if controls
        else [Event.id < 0]
    )
    baseline_total = int(db.scalar(select(func.coalesce(func.sum(Event.connections), 0)).where(*baseline)))
    window_total = int(db.scalar(select(func.coalesce(func.sum(Event.connections), 0)).where(*window))) or 1
    # Cross-event counts are computed from source windows, independent of worker order.
    related = db.scalars(
        select(BlockEvent).where(
            BlockEvent.state.in_(["confirmed", "recovered", "manual"]),
            BlockEvent.detected_at >= now() - timedelta(days=config["incident_retention_days"]),
        )
    ).all()
    db.execute(delete(Correlation).where(Correlation.block_event_id == incident.id))
    for kind, field in ENTITIES.items():
        key_expression = (
            func.host(field)
            if kind in ("source_ip", "destination_ip") and db.bind.dialect.name == "postgresql"
            else cast(field, String)
        )
        source_presence = (
            select(
                key_expression.label("entity"),
                BlockEvent.id.label("incident"),
                BlockEvent.vps_id.label("vps"),
            )
            .select_from(Event)
            .join(
                BlockEvent,
                (Event.vps_id == BlockEvent.vps_id)
                & (Event.bucket_start >= BlockEvent.window_start)
                & (Event.bucket_start < BlockEvent.window_end),
            )
            .where(
                BlockEvent.state.in_(["confirmed", "recovered", "manual"]),
                field.is_not(None),
                BlockEvent.detected_at >= now() - timedelta(days=config["incident_retention_days"]),
            )
        )
        saved_presence = (
            select(Correlation.entity_key, BlockEvent.id, BlockEvent.vps_id)
            .join(BlockEvent, Correlation.block_event_id == BlockEvent.id)
            .where(
                Correlation.entity_type == kind,
                BlockEvent.state.in_(["confirmed", "recovered", "manual"]),
                BlockEvent.detected_at >= now() - timedelta(days=config["incident_retention_days"]),
            )
        )
        presence = source_presence.union(saved_presence).subquery()
        repeats = {
            key: (count, vps_count)
            for key, count, vps_count in db.execute(
                select(
                    presence.c.entity,
                    func.count(func.distinct(presence.c.incident)),
                    func.count(func.distinct(presence.c.vps)),
                ).group_by(presence.c.entity)
            )
        }
        baseline_counts = dict(
            db.execute(
                select(field, func.sum(Event.connections))
                .where(*baseline, field.is_not(None))
                .group_by(field)
            ).all()
        )
        # Stream grouped results; never materialize raw connection rows.
        groups = db.execute(
            select(
                field,
                func.sum(Event.connections),
                func.min(Event.first_seen),
                func.max(Event.last_seen),
                func.count(func.distinct(Event.user_id)),
                func.count(func.distinct(Event.source_ip)),
            )
            .where(*window, field.is_not(None))
            .group_by(field)
            .execution_options(yield_per=500)
        )
        for key, connections, first, last, users, ips in groups:
            connections = int(connections)
            if kind == "domain" and str(key) in config["domain_ignore"]:
                continue
            share = connections / window_total
            base_connections = int(baseline_counts.get(key, 0))
            base_share = (base_connections + 1) / (baseline_total + 1)
            lift = share / base_share if baseline_total else 1
            appearances, vps_count = repeats.get(str(key), (0, 0))
            proximity = max(0, 1 - (end - utc(last)).total_seconds() / duration)
            score = calculate_score(
                appearances / max(1, len(related)), lift, proximity, vps_count, share, config["weights"]
            )
            db.add(
                Correlation(
                    block_event_id=incident.id,
                    entity_type=kind,
                    entity_key=str(key),
                    connections=connections,
                    score=score,
                    details=dict(
                        baseline_method=method,
                        baseline_connections=base_connections,
                        baseline_total=baseline_total,
                        baseline_lift=lift,
                        insufficient_baseline=not baseline_total,
                        appearances=appearances,
                        total_events=len(related),
                        cross_vps=vps_count,
                        first_seen=utc(first).isoformat(),
                        last_seen=utc(last).isoformat(),
                        distinct_users=users,
                        distinct_source_ips=ips,
                        event_share=share,
                        temporal_proximity=proximity,
                        weights=config["weights"],
                        formula="100 * weighted(presence, log2(lift)/4, proximity, (vps-1)/4, share) * clamp((lift-1)/3)",
                    ),
                )
            )
    db.flush()
    refresh_cross_event(db, incident.id)


def refresh_cross_event(db, incident_id):
    """Refresh historical scores for entities affected by a newly calculated incident."""
    config = settings(db)
    eligible = [
        BlockEvent.state.in_(["confirmed", "recovered", "manual"]),
        BlockEvent.detected_at >= now() - timedelta(days=config["incident_retention_days"]),
    ]
    total = db.scalar(select(func.count()).select_from(BlockEvent).where(*eligible)) or 1
    for kind in ENTITIES:
        keys = select(Correlation.entity_key).where(
            Correlation.block_event_id == incident_id, Correlation.entity_type == kind
        )
        counts = {
            key: (events, hosts)
            for key, events, hosts in db.execute(
                select(
                    Correlation.entity_key,
                    func.count(func.distinct(Correlation.block_event_id)),
                    func.count(func.distinct(BlockEvent.vps_id)),
                )
                .join(BlockEvent, Correlation.block_event_id == BlockEvent.id)
                .where(Correlation.entity_type == kind, Correlation.entity_key.in_(keys), *eligible)
                .group_by(Correlation.entity_key)
            )
        }
        rows = db.scalars(
            select(Correlation)
            .where(Correlation.entity_type == kind, Correlation.entity_key.in_(keys))
            .execution_options(yield_per=500)
        )
        for row in rows:
            appearances, hosts = counts.get(row.entity_key, (0, 0))
            details = dict(row.details, appearances=appearances, total_events=total, cross_vps=hosts)
            row.score = calculate_score(
                appearances / total,
                details["baseline_lift"],
                details["temporal_proximity"],
                hosts,
                details["event_share"],
                config["weights"],
            )
            row.details = details
