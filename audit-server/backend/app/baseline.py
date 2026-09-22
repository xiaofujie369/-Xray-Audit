"""Transactional hourly counts, with keyed pseudonyms instead of browsing history."""

import hashlib
import hmac
import os
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .db import utc
from .models import BlockEvent, HourlyBaseline


def backfill_batch(db, limit=1000):
    from .models import Event, Setting
    checkpoint = db.scalar(select(Setting).where(Setting.key == "baseline_backfill").with_for_update())
    if checkpoint is None or checkpoint.value["cursor"] >= checkpoint.value["max_id"]:
        return False
    rows = db.scalars(select(Event).where(Event.id > checkpoint.value["cursor"],
        Event.id <= checkpoint.value["max_id"]).order_by(Event.id).limit(limit)).all()
    accumulate(db, [{column.name: getattr(row, column.name) for column in Event.__table__.columns}
                    for row in rows])
    checkpoint.value = {"cursor": rows[-1].id if rows else checkpoint.value["max_id"],
                        "max_id": checkpoint.value["max_id"]}
    if checkpoint.value["cursor"] >= checkpoint.value["max_id"]:
        db.execute(update(BlockEvent).values(investigation_dirty=True))
    return bool(rows)

FIELDS = {"user": "user_id", "source_ip": "source_ip", "domain": "destination_domain",
          "destination_ip": "destination_ip", "node": "node_id"}


def pseudonym(kind, value):
    secret = os.environ.get("APP_SECRET", "development-only")
    return hmac.new(secret.encode(), (kind + ":" + str(value)).encode(), hashlib.sha256).hexdigest()


def incident_end(incident, until):
    if incident.recovered_at:
        return utc(incident.recovered_at)
    if incident.state in ("suspected", "confirmed", "manual"):
        return until
    return utc(incident.window_end)


def accumulate(db, rows):
    counts = defaultdict(int)
    for row in rows:
        hour = utc(row["bucket_start"]).replace(minute=0, second=0, microsecond=0)
        base = (row["vps_id"], hour)
        counts[(*base, "total", "all")] += row["connections"]
        for kind, field in FIELDS.items():
            if row.get(field) is not None:
                counts[(*base, kind, pseudonym(kind, row[field]))] += row["connections"]
    insert = pg_insert if db.bind.dialect.name == "postgresql" else sqlite_insert
    ordered = sorted(counts.items())
    for offset in range(0, len(ordered), 100):
        values = [{"vps_id": vps, "hour_start": hour, "entity_type": kind,
                   "entity_hash": key, "connections": count}
                  for (vps, hour, kind, key), count in ordered[offset:offset + 100]]
        stmt = insert(HourlyBaseline).values(values)
        db.execute(stmt.on_conflict_do_update(
            index_elements=["vps_id", "hour_start", "entity_type", "entity_hash"],
            set_={"connections": HourlyBaseline.connections + stmt.excluded.connections}))


def normal_hours(db, incident, start):
    anchor = start.replace(minute=0, second=0, microsecond=0)
    incidents = db.scalars(select(BlockEvent).where(
        BlockEvent.vps_id == incident.vps_id,
        or_(BlockEvent.window_end > anchor - timedelta(days=8),
            BlockEvent.recovered_at > anchor - timedelta(days=8),
            BlockEvent.state.in_(["suspected", "confirmed", "manual"])),
        BlockEvent.window_start < start)).all()
    def clean(hour):
        return not any(utc(row.window_start) < hour + timedelta(hours=1)
                       and incident_end(row, start) > hour for row in incidents)
    candidates = [anchor - timedelta(days=day) for day in range(1, 8)]
    available = set(db.scalars(select(HourlyBaseline.hour_start).where(
        HourlyBaseline.vps_id == incident.vps_id, HourlyBaseline.entity_type == "total",
        HourlyBaseline.hour_start.in_([hour for hour in candidates if clean(hour)]))))
    hours = [hour for hour in candidates if hour in {utc(h) for h in available} and clean(hour)]
    method = "hourly_same_hour_previous_7_days"
    if len(hours) < 2:
        hours = [anchor - timedelta(hours=h) for h in range(1, 25) if clean(anchor - timedelta(hours=h))]
        method = "hourly_previous_24h_excluding_incidents"
    filters = [HourlyBaseline.vps_id == incident.vps_id, HourlyBaseline.hour_start.in_(hours)]
    total = int(db.scalar(select(func.coalesce(func.sum(HourlyBaseline.connections), 0))
                          .where(*filters, HourlyBaseline.entity_type == "total")))
    counts = {(kind, key): int(count) for kind, key, count in db.execute(
        select(HourlyBaseline.entity_type, HourlyBaseline.entity_hash, func.sum(HourlyBaseline.connections))
        .where(*filters, HourlyBaseline.entity_type != "total")
        .group_by(HourlyBaseline.entity_type, HourlyBaseline.entity_hash))}
    return total, counts, method
