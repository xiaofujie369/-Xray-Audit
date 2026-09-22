"""Reachability evidence and explainable association, never causal attribution."""

import math
from datetime import timedelta

from sqlalchemy import String, cast, delete, func, or_, select

from .baseline import incident_end, normal_hours, pseudonym
from .db import now, utc
from .models import (
    VPS,
    BlockEvent,
    Correlation,
    Event,
    Identity,
    InvestigationSnapshot,
    Job,
    ProbeResult,
    Target,
)
from .settings import control_revision, settings


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
            Identity.kind == "probes", Identity.enabled.is_(True)
        )
    ).all()
    bad, good, evidence, bad_times, good_times = set(), set(), [], [], []
    outside_good = set()
    outside_bad = set()
    verified_bad = set()
    expected_controls = control_revision(config["control_targets"])
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
        group = probe.independence_group or "unclassified"
        evidence.append(
            {
                "probe": probe.name,
                "mainland": probe.mainland,
                "group": group,
                "results": [
                    dict(
                        time=utc(row.started_at).isoformat(),
                        success=row.success,
                        control_ok=row.control_ok,
                        controls_current=row.control_revision == expected_controls,
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
        if not probe.mainland:
            if len(failures) >= config["fail_consecutive"]:
                outside_bad.add(group)
            if (probe.independence_group and len(successes) >= config["recover_consecutive"]
                    and all(r.control_revision == expected_controls for r in successes[:config["recover_consecutive"]])):
                outside_good.add(group)
            continue
        if len(failures) >= config["fail_consecutive"]:
            bad.add(group)
            bad_times.append(min(utc(r.started_at) for r in failures))
            if (probe.independence_group and all(r.control_revision == expected_controls
                    for r in failures[:config["fail_consecutive"]])):
                verified_bad.add(group)
        if len(successes) >= config["recover_consecutive"]:
            good.add(group)
        good_times.extend(utc(r.started_at) for r in rows if r.success and r.control_ok)
    # Conflicting observations from one network cannot count as independent agreement.
    conflicting = bad & good
    bad -= conflicting
    good -= conflicting
    verified_bad -= conflicting
    outside_good -= bad | good | outside_bad
    active = db.scalar(
        select(BlockEvent)
        .where(BlockEvent.target_id == target_id, BlockEvent.state.in_(["suspected", "confirmed"]))
        .order_by(BlockEvent.detected_at.desc())
        .with_for_update().limit(1)
    )
    host = db.get(VPS, target.vps_id)
    host_healthy = bool(
        host and host.last_heartbeat_at
        and utc(host.last_heartbeat_at) >= now() - timedelta(seconds=180)
        and (host.health or {}).get("xray_running") is True
    )
    missing = []
    if len(bad) < max(2, config["min_distinct_probes"]):
        missing.append("insufficient_independent_mainland_failures")
    if not outside_good:
        missing.append("no_recent_outside_mainland_success")
    if not config["control_targets"]:
        missing.append("no_control_targets_configured")
    if len(verified_bad) < max(2, config["min_distinct_probes"]):
        missing.append("insufficient_current_control_evidence_or_network_groups")
    if not host_healthy:
        missing.append("no_recent_healthy_xray_heartbeat")
    state = "confirmed" if bad and not missing else "suspected" if bad else None
    if active and not bad and len(good) >= config["min_distinct_probes"]:
        state = "recovered" if active.state == "confirmed" else "false_positive"
    if state is None:
        return
    previous = active.state if active else None
    if active is None:
        first_bad = min(bad_times)
        last_good = db.scalar(
            select(func.max(ProbeResult.started_at)).join(
                Identity, Identity.id == ProbeResult.probe_id
            ).where(
                Identity.mainland.is_(True),
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
    if state == "suspected":
        active.confidence = min(0.49, active.confidence)
    if state in ("recovered", "false_positive"):
        active.recovered_at = now()
    signature = {"state": state, "mainland_bad": sorted(bad), "mainland_good": sorted(good),
                 "verified_bad": sorted(verified_bad), "outside_good": sorted(outside_good),
                 "host_healthy": host_healthy, "missing": missing}
    prior_signature = active.evidence[-1].get("signature") if active.evidence else None
    if previous != state or prior_signature != signature:
        active.investigation_dirty = True
        active.evidence = list(active.evidence or []) + [
            {
                "state": state,
                "time": now().isoformat(),
                "observations": evidence,
                "single_network": count < 2,
                "control_targets_configured": bool(config["control_targets"]),
                "outside_mainland_success_groups": sorted(outside_good),
                "healthy_xray_heartbeat": host_healthy,
                "missing_confirmation_evidence": missing if state in ("suspected", "confirmed") else [],
                "classification_version": 2,
                "confirmation_criteria_met": bool(bad) and not missing,
                "interpretation": "Regional blocking evidence; not proof of mechanism or cause.",
                "signature": signature,
            }
        ]
        if state == "confirmed" and bad_times:
            active.first_known_bad_at = min(utc(active.first_known_bad_at), min(bad_times))
            active.window_end = active.first_known_bad_at
            active.window_start = active.window_end - timedelta(minutes=config["lookback_minutes"])
        # Keep the opening evidence plus recent changes bounded during long incidents.
        if len(active.evidence) > 200:
            active.evidence = active.evidence[:1] + active.evidence[-199:]
        if previous != state:
            db.add(Job(kind="notify", payload={"event": state, "vps_id": target.vps_id, "incident": active.id}))


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
    saved = db.scalar(select(InvestigationSnapshot).where(
        InvestigationSnapshot.block_event_id == event_id
    ).order_by(InvestigationSnapshot.created_at.desc(), InvestigationSnapshot.id.desc()).limit(1))
    if saved:
        saved_window = saved.payload.get("windows", {}).get(str(int(duration // 60)))
        if saved_window and saved_window.get("aggregate_rows", 0) > db.scalar(
            select(func.count()).select_from(Event).where(*window)
        ):
            # Do not replace a complete captured score with a retention-truncated window.
            refresh_cross_event(db, event_id)
            return
    if db.scalar(select(Event.id).where(*window).limit(1)) is None and db.scalar(
        select(Correlation.id).where(Correlation.block_event_id == event_id).limit(1)
    ):
        # Preserve the historical snapshot after detailed source retention expires.
        return
    # Control windows exclude every incident window, including suspected incidents.
    previous = db.scalars(
        select(BlockEvent).where(
            BlockEvent.vps_id == incident.vps_id,
            or_(BlockEvent.window_end >= start - timedelta(days=8),
                BlockEvent.recovered_at >= start - timedelta(days=8),
                BlockEvent.state.in_(["suspected", "confirmed", "manual"])),
            BlockEvent.window_start < start,
        )
    ).all()
    controls = []
    for days in range(1, 8):
        a, b = start - timedelta(days=days), end - timedelta(days=days)
        if not any(utc(e.window_start) < b and incident_end(e, start) > a for e in previous):
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
            if not any(utc(e.window_start) < b and incident_end(e, start) > a for e in previous):
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
    hourly_total, hourly_counts, hourly_method = normal_hours(db, incident, start)
    if hourly_total:
        baseline_total = hourly_total
        method = hourly_method
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
            base_connections = (hourly_counts.get((kind, pseudonym(kind, key)), 0)
                                if hourly_total else int(baseline_counts.get(key, 0)))
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
    changed_incidents = set()
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
            score = calculate_score(
                appearances / total,
                details["baseline_lift"],
                details["temporal_proximity"],
                hosts,
                details["event_share"],
                config["weights"],
            )
            if row.score != score or row.details != details:
                row.score = score
                row.details = details
                if row.block_event_id != incident_id:
                    changed_incidents.add(row.block_event_id)
    for changed_id in changed_incidents:
        db.add(Job(kind="snapshot", payload={"id": changed_id}))
