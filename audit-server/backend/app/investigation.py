"""Bounded, versioned investigation evidence; never causal attribution."""

import hashlib
import json
from datetime import timedelta

from sqlalchemy import func, select

from .analysis import ENTITIES
from .db import utc
from .models import BlockEvent, Correlation, Event, InvestigationSnapshot


def capture(db, event_id):
    incident = db.scalar(select(BlockEvent).where(BlockEvent.id == event_id).with_for_update())
    if incident is None:
        return
    previous = db.scalar(select(InvestigationSnapshot).where(
        InvestigationSnapshot.block_event_id == event_id
    ).order_by(InvestigationSnapshot.created_at.desc(), InvestigationSnapshot.id.desc()).limit(1))
    end = utc(incident.window_end)
    windows = {}
    for minutes in (15, 30, 60):
        start = end - timedelta(minutes=minutes)
        filters = [Event.vps_id == incident.vps_id, Event.bucket_start >= start, Event.bucket_start < end]
        count, connections, first, last = db.execute(select(
            func.count(Event.id), func.coalesce(func.sum(Event.connections), 0),
            func.min(Event.bucket_start), func.max(Event.bucket_start)
        ).where(*filters)).one()
        # A missing source window must not erase previously captured evidence.
        saved = (previous.payload.get("windows", {}) if previous else {}).get(str(minutes))
        if saved and count < saved.get("aggregate_rows", 0):
            windows[str(minutes)] = saved
            continue
        entities = {}
        for kind, field in ENTITIES.items():
            rows = db.execute(select(field, func.sum(Event.connections).label("connections"))
                .where(*filters, field.is_not(None)).group_by(field)
                .order_by(func.sum(Event.connections).desc(), field).limit(50)).all()
            entities[kind] = [{"key": str(key), "connections": int(total)} for key, total in rows]
        dimensions = [Event.node_id, Event.user_id, Event.source_ip, Event.destination_domain,
                      Event.destination_ip, Event.destination_port, Event.network, Event.decision]
        samples = db.execute(select(*dimensions, func.sum(Event.connections),
            func.min(Event.first_seen), func.max(Event.last_seen)).where(*filters)
            .group_by(*dimensions).order_by(func.sum(Event.connections).desc(), *dimensions).limit(100)).all()
        connection_groups = []
        for row in samples:
            group = {column.key: (str(value) if column.key in ("source_ip", "destination_ip") and value is not None else value)
                     for column, value in zip(dimensions, row[:len(dimensions)])}
            group.update(connections=int(row[-3]), first_seen=utc(row[-2]).isoformat(), last_seen=utc(row[-1]).isoformat())
            connection_groups.append(group)
        windows[str(minutes)] = {
            "start": start.isoformat(), "end": end.isoformat(),
            "aggregate_rows": int(count), "connections": int(connections),
            "first_available_bucket": utc(first).isoformat() if first else None,
            "last_available_bucket": utc(last).isoformat() if last else None,
            "coverage": "observed_records_only" if count else "no_records",
            "entities": entities, "entity_limit": 50,
            "connection_groups": connection_groups, "connection_group_limit": 100,
        }
    correlations = db.scalars(select(Correlation).where(Correlation.block_event_id == event_id)
        .order_by(Correlation.score.desc(), Correlation.entity_type, Correlation.entity_key).limit(100)).all()
    payload = {
        "schema_version": 1, "event_id": event_id, "state": incident.state,
        "vps_id": incident.vps_id, "target_ip": str(incident.target_ip),
        "target_port": incident.target_port,
        "last_known_good_at": utc(incident.last_known_good_at).isoformat() if incident.last_known_good_at else None,
        "first_known_bad_at": utc(incident.first_known_bad_at).isoformat(),
        "recovered_at": utc(incident.recovered_at).isoformat() if incident.recovered_at else None,
        "probe_evidence": incident.evidence, "windows": windows,
        "correlations": [{"entity_type": row.entity_type, "key": row.entity_key,
                          "score": row.score, "connections": row.connections,
                          "details": row.details} for row in correlations],
        "interpretation": "Correlation only. Missing records do not establish absence of activity.",
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    existing = db.scalar(select(InvestigationSnapshot).where(
        InvestigationSnapshot.block_event_id == event_id, InvestigationSnapshot.content_hash == digest))
    if existing:
        return existing
    snapshot = InvestigationSnapshot(block_event_id=event_id, content_hash=digest, payload=payload)
    db.add(snapshot)
    db.flush()
    return snapshot
