import uuid

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET, JSONB

from .db import Base, now

IP = String(45).with_variant(INET(), "postgresql")
DOCUMENT = JSON().with_variant(JSONB(), "postgresql")
SERIAL = BigInteger().with_variant(Integer(), "sqlite")


def uid():
    return str(uuid.uuid4())


class VPS(Base):
    __tablename__ = "vps"
    id = Column(String(36), primary_key=True, default=uid)
    name = Column(String(128), nullable=False)
    region = Column(String(128), default="")
    provider = Column(String(128), default="")
    hostname = Column(String(253))
    agent_version = Column(String(40))
    xray_version = Column(String(40))
    enabled = Column(Boolean, default=True, nullable=False)
    last_heartbeat_at = Column(DateTime(timezone=True))
    health = Column(DOCUMENT, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class Identity(Base):
    __tablename__ = "agent_identities"
    id = Column(String(36), primary_key=True, default=uid)
    kind = Column(String(10), nullable=False)
    name = Column(String(128), nullable=False)
    region = Column(String(128), default="")
    independence_group = Column(String(128), default="")
    mainland = Column(Boolean, default=False, nullable=False)
    vps_id = Column(ForeignKey("vps.id"), nullable=True, index=True)
    token_hash = Column(String(64), nullable=False, unique=True)
    enabled = Column(Boolean, default=True, nullable=False)
    last_heartbeat_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class IPHistory(Base):
    __tablename__ = "vps_ip_history"
    id = Column(SERIAL, primary_key=True)
    vps_id = Column(ForeignKey("vps.id"), nullable=False, index=True)
    address = Column(IP, nullable=False, index=True)
    family = Column(Integer, nullable=False)
    first_seen = Column(DateTime(timezone=True), default=now, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=now, nullable=False)
    current = Column(Boolean, default=True, nullable=False)


class Enrollment(Base):
    __tablename__ = "enrollment_tokens"
    token_hash = Column(String(64), primary_key=True)
    kind = Column(String(10), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True))
    options = Column(DOCUMENT, default=dict, nullable=False)


class Admin(Base):
    __tablename__ = "admin_users"
    id = Column(String(36), primary_key=True, default=uid)
    email = Column(String(254), nullable=False, unique=True)
    password_hash = Column(Text, nullable=False)
    role = Column(String(10), nullable=False, default="viewer")
    enabled = Column(Boolean, nullable=False, default=True)


class LoginSession(Base):
    __tablename__ = "login_sessions"
    token_hash = Column(String(64), primary_key=True)
    admin_id = Column(ForeignKey("admin_users.id"), nullable=False)
    csrf_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)


class AuditLog(Base):
    __tablename__ = "admin_audit_log"
    id = Column(SERIAL, primary_key=True)
    actor = Column(String(254), nullable=False)
    action = Column(String(64), nullable=False)
    detail = Column(DOCUMENT, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False, index=True)


class Batch(Base):
    __tablename__ = "received_batches"
    agent_id = Column(ForeignKey("agent_identities.id"), primary_key=True)
    batch_id = Column(String(80), primary_key=True)
    kind = Column(String(12), nullable=False)
    body_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False, index=True)


class Event(Base):
    __tablename__ = "audit_events_1m"
    id = Column(SERIAL, primary_key=True)
    vps_id = Column(ForeignKey("vps.id"), nullable=False)
    bucket_start = Column(DateTime(timezone=True), nullable=False, index=True)
    bucket_seconds = Column(Integer, nullable=False)
    node_id = Column(BigInteger)
    user_id = Column(BigInteger)
    source_ip = Column(IP)
    destination_domain = Column(String(253))
    destination_ip = Column(IP)
    destination_port = Column(Integer)
    network = Column(String(3), nullable=False)
    inbound_tag = Column(String(128))
    outbound_tag = Column(String(128))
    decision = Column(String(8), nullable=False)
    connections = Column(BigInteger, nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    __table_args__ = tuple(
        Index("ix_event_" + field + "_time", field, "bucket_start")
        for field in ("vps_id", "user_id", "source_ip", "destination_domain", "destination_ip", "node_id")
    )


class Traffic(Base):
    __tablename__ = "audit_user_traffic"
    id = Column(SERIAL, primary_key=True)
    vps_id = Column(ForeignKey("vps.id"), nullable=False)
    node_id = Column(BigInteger)
    user_id = Column(BigInteger, nullable=False)
    interval_start = Column(DateTime(timezone=True), nullable=False, index=True)
    interval_end = Column(DateTime(timezone=True), nullable=False)
    uplink_bytes = Column(BigInteger, nullable=False)
    downlink_bytes = Column(BigInteger, nullable=False)
    __table_args__ = (
        Index("ix_traffic_user_time", "user_id", "interval_start"),
        Index("ix_traffic_vps_time", "vps_id", "interval_start"),
    )


class Target(Base):
    __tablename__ = "probe_targets"
    id = Column(String(36), primary_key=True, default=uid)
    vps_id = Column(ForeignKey("vps.id"), nullable=False, index=True)
    address = Column(IP, nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(8), nullable=False, default="tcp")
    server_name = Column(String(253))
    path = Column(String(256), default="/")
    enabled = Column(Boolean, nullable=False, default=True)
    __table_args__ = (UniqueConstraint("vps_id", "address", "port", "protocol"),)


class ProbeResult(Base):
    __tablename__ = "probe_results"
    id = Column(SERIAL, primary_key=True)
    probe_id = Column(ForeignKey("agent_identities.id"), nullable=False)
    target_id = Column(ForeignKey("probe_targets.id"), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=False, index=True)
    success = Column(Boolean, nullable=False)
    control_ok = Column(Boolean, nullable=False)
    control_revision = Column(String(64))
    latency_ms = Column(Float)
    error_class = Column(String(32))
    __table_args__ = (
        UniqueConstraint("probe_id", "target_id", "started_at"),
        Index("ix_probe_target_time", "target_id", "started_at"),
    )


class BlockEvent(Base):
    __tablename__ = "block_events"
    id = Column(String(36), primary_key=True, default=uid)
    vps_id = Column(ForeignKey("vps.id"), nullable=False, index=True)
    target_id = Column(ForeignKey("probe_targets.id"))
    target_ip = Column(IP, nullable=False)
    target_port = Column(Integer)
    state = Column(String(20), nullable=False)
    source = Column(String(10), nullable=False, default="probe")
    detected_at = Column(DateTime(timezone=True), default=now, nullable=False, index=True)
    window_start = Column(DateTime(timezone=True), nullable=False)
    window_end = Column(DateTime(timezone=True), nullable=False)
    last_known_good_at = Column(DateTime(timezone=True))
    first_known_bad_at = Column(DateTime(timezone=True), nullable=False)
    recovered_at = Column(DateTime(timezone=True))
    confidence = Column(Float, nullable=False, default=0)
    probe_count = Column(Integer, nullable=False, default=0)
    evidence = Column(DOCUMENT, nullable=False, default=list)
    notes = Column(String(2000), default="")
    investigation_dirty = Column(Boolean, default=True, nullable=False, server_default="true")


class Correlation(Base):
    __tablename__ = "block_event_correlations"
    id = Column(SERIAL, primary_key=True)
    block_event_id = Column(ForeignKey("block_events.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type = Column(String(20), nullable=False)
    entity_key = Column(String(253), nullable=False)
    connections = Column(BigInteger, nullable=False)
    score = Column(Float, nullable=False)
    details = Column(DOCUMENT, nullable=False)
    __table_args__ = (
        UniqueConstraint("block_event_id", "entity_type", "entity_key"),
        Index("ix_correlation_entity", "entity_type", "entity_key"),
    )


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String(80), primary_key=True)
    value = Column(DOCUMENT, nullable=False)


class InvestigationSnapshot(Base):
    __tablename__ = "investigation_snapshots"
    id = Column(String(36), primary_key=True, default=uid)
    block_event_id = Column(ForeignKey("block_events.id", ondelete="CASCADE"), nullable=False, index=True)
    content_hash = Column(String(64), nullable=False)
    payload = Column(DOCUMENT, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)
    __table_args__ = (UniqueConstraint("block_event_id", "content_hash"),)


class HourlyBaseline(Base):
    __tablename__ = "hourly_baselines"
    vps_id = Column(ForeignKey("vps.id"), primary_key=True)
    hour_start = Column(DateTime(timezone=True), primary_key=True, index=True)
    entity_type = Column(String(20), primary_key=True)
    entity_hash = Column(String(64), primary_key=True)
    connections = Column(BigInteger, nullable=False)


class AIReport(Base):
    __tablename__ = "ai_reports"
    id = Column(String(36), primary_key=True, default=uid)
    snapshot_id = Column(ForeignKey("investigation_snapshots.id", ondelete="CASCADE"), nullable=False, unique=True)
    status = Column(String(16), default="pending", nullable=False, index=True)
    model = Column(String(128), nullable=False, default="")
    result = Column(DOCUMENT, nullable=False, default=dict)
    error_code = Column(String(64))
    attempts = Column(Integer, nullable=False, default=0)
    available_at = Column(DateTime(timezone=True), default=now, nullable=False, index=True)
    lease_token = Column(String(36))
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)
    finished_at = Column(DateTime(timezone=True))
    last_attempt_at = Column(DateTime(timezone=True))


class Job(Base):
    __tablename__ = "durable_jobs"
    id = Column(String(36), primary_key=True, default=uid)
    kind = Column(String(32), nullable=False)
    payload = Column(DOCUMENT, nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    available_at = Column(DateTime(timezone=True), default=now, nullable=False, index=True)


class Counter(Base):
    __tablename__ = "operational_counters"
    name = Column(String(80), primary_key=True)
    value = Column(BigInteger, nullable=False, default=0)
