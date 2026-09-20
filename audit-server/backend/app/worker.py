import json
import logging
import os
import shutil
import time
from datetime import timedelta
from urllib.request import Request, urlopen

from celery import Celery
from sqlalchemy import delete, select

from .analysis import correlate, transition
from .db import Session, now, utc
from .models import (
    VPS,
    AuditLog,
    Batch,
    BlockEvent,
    Correlation,
    Event,
    Identity,
    Job,
    LoginSession,
    ProbeResult,
    Setting,
    Traffic,
)
from .settings import settings

celery = Celery("audit", broker=os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    beat_schedule={
        "drain": {"task": "audit.drain", "schedule": 5.0},
        "retention": {"task": "audit.retention", "schedule": 60.0},
        "monitor": {"task": "audit.monitor", "schedule": 60.0},
    },
)


def notify(payload):
    destinations = []
    if os.environ.get("WEBHOOK_ENABLED", "false").lower() == "true":
        destinations.append((os.environ["WEBHOOK_URL"], payload))
    if os.environ.get("TELEGRAM_ENABLED", "false").lower() == "true":
        destinations.append(
            (
                "https://api.telegram.org/bot" + os.environ["TELEGRAM_BOT_TOKEN"] + "/sendMessage",
                {"chat_id": os.environ["TELEGRAM_CHAT_ID"], "text": json.dumps(payload, ensure_ascii=False)},
            )
        )
    for url, body in destinations:
        if not url.startswith("https://"):
            raise ValueError("notification HTTPS required")
        with urlopen(
            Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}),
            timeout=10,
        ) as response:
            response.read(4096)


@celery.task(name="audit.drain")
def drain():
    for _ in range(100):
        with Session() as db:
            job = db.scalar(
                select(Job)
                .where(Job.available_at <= now())
                .order_by(Job.available_at)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if job is None:
                return
            job_id = job.id
            try:
                if job.kind == "transition":
                    transition(db, job.payload["id"])
                elif job.kind == "correlate":
                    correlate(db, job.payload["id"])
                elif job.kind == "notify":
                    notify(job.payload)
                else:
                    raise ValueError("unknown job kind")
                db.delete(job)
                db.commit()
            except Exception as error:
                db.rollback()
                job = db.get(Job, job_id)
                if job:
                    job.attempts += 1
                    if job.attempts == 1 or job.attempts % 10 == 0:
                        logging.warning(
                            "audit_job_failed kind=%s error_type=%s attempts=%s",
                            job.kind,
                            type(error).__name__,
                            job.attempts,
                        )
                    job.available_at = now() + timedelta(seconds=min(3600, 2 ** min(job.attempts, 12)))
                    db.commit()


@celery.task(name="audit.retention")
def retention():
    deadline = time.monotonic() + 40
    with Session() as db:
        config = settings(db)
        specs = [
            (Event, Event.bucket_start, config["event_retention_days"]),
            (Traffic, Traffic.interval_start, config["traffic_retention_days"]),
            (ProbeResult, ProbeResult.started_at, config["incident_retention_days"]),
            (AuditLog, AuditLog.created_at, config["admin_log_retention_days"]),
        ]
        for model, timestamp, days in specs:
            # Bounded deletes avoid huge locks and transactions.
            for _ in range(100):
                ids = (
                    select(model.id)
                    .where(timestamp < now() - timedelta(days=days))
                    .order_by(timestamp)
                    .limit(10000)
                )
                removed = db.execute(delete(model).where(model.id.in_(ids)))
                db.commit()
                if removed.rowcount < 10000 or time.monotonic() >= deadline:
                    break
        expired = (
            select(BlockEvent.id)
            .where(BlockEvent.detected_at < now() - timedelta(days=config["incident_retention_days"]))
            .limit(1000)
        )
        ids = list(db.scalars(expired))
        correlation_expired = (
            select(Correlation.id)
            .join(BlockEvent, Correlation.block_event_id == BlockEvent.id)
            .where(BlockEvent.detected_at < now() - timedelta(days=config["correlation_retention_days"]))
            .limit(10000)
        )
        db.execute(delete(Correlation).where(Correlation.id.in_(correlation_expired)))
        db.execute(delete(Correlation).where(Correlation.block_event_id.in_(ids)))
        db.execute(delete(BlockEvent).where(BlockEvent.id.in_(ids)))
        # Dedupe horizon must be greater than maximum ingest age, not event retention.
        db.execute(delete(Batch).where(Batch.created_at < now() - timedelta(days=100)))
        db.execute(delete(LoginSession).where(LoginSession.expires_at < now()))
        db.commit()


@celery.task(name="audit.monitor")
def monitor():
    """Durable edge-triggered health notifications, quiet until state changes."""
    with Session() as db:
        config = settings(db)
        for identity in db.scalars(select(Identity).where(Identity.enabled.is_(True))):
            threshold = 180 if identity.kind == "agents" else config["probe_interval_seconds"] * 3
            reference = utc(identity.last_heartbeat_at or identity.created_at)
            offline = (now() - reference).total_seconds() > threshold
            alert(
                db,
                "offline:" + identity.id,
                offline,
                {
                    "event": "agent_offline" if identity.kind == "agents" else "probe_offline",
                    "name": identity.name,
                },
            )
        for vps in db.scalars(select(VPS)):
            health = vps.health or {}
            near_full = health.get("spool_usage_ratio", 0) >= 0.8
            alert(db, "spool:" + vps.id, near_full, {"event": "spool_near_full", "vps_id": vps.id})
        usage = shutil.disk_usage("/")
        alert(db, "central_disk", usage.free / usage.total < 0.1, {"event": "central_disk_near_full"})
        db.merge(Setting(key="worker_last_seen", value=now().isoformat()))
        db.commit()


def alert(db, key, active, payload):
    row = db.get(Setting, "alert:" + key)
    previous = row.value if row else False
    if active and not previous:
        db.add(Job(kind="notify", payload=payload))
    if previous != active or row is None:
        db.merge(Setting(key="alert:" + key, value=active))
