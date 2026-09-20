import ipaddress
from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent.access_parser import normalize_domain, normalize_ip

from .db import now


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EventInput(Strict):
    bucket_start: datetime
    bucket_seconds: int = Field(ge=1, le=3600)
    node_id: int | None = Field(default=None, ge=0, le=9223372036854775807)
    user_id: int | None = Field(default=None, ge=0, le=9223372036854775807)
    source_ip: str | None = None
    destination_domain: str | None = Field(default=None, max_length=253)
    destination_ip: str | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    network: Literal["tcp", "udp"]
    inbound_tag: str | None = Field(default=None, max_length=128)
    outbound_tag: str | None = Field(default=None, max_length=128)
    decision: Literal["accepted", "rejected"]
    connections: int = Field(ge=1, le=2147483647)
    first_seen: datetime
    last_seen: datetime

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def ip(cls, value):
        return normalize_ip(value) if value else None

    @field_validator("destination_domain")
    @classmethod
    def domain(cls, value):
        return normalize_domain(value) if value else None

    @model_validator(mode="after")
    def times(self):
        for value in (self.bucket_start, self.first_seen, self.last_seen):
            validate_time(value)
        if (
            not self.bucket_start
            <= self.first_seen
            <= self.last_seen
            < self.bucket_start + timedelta(seconds=self.bucket_seconds)
        ):
            raise ValueError("timestamps outside bucket")
        return self


def validate_time(value):
    if value.tzinfo is None or not now() - timedelta(days=90) <= value <= now() + timedelta(minutes=5):
        raise ValueError("timestamp must be aware and within ingest tolerance")
    return value


class TrafficInput(Strict):
    node_id: int | None = Field(default=None, ge=0, le=9223372036854775807)
    user_id: int = Field(ge=0, le=9223372036854775807)
    interval_start: datetime
    interval_end: datetime
    uplink_bytes: int = Field(ge=0, le=9223372036854775807)
    downlink_bytes: int = Field(ge=0, le=9223372036854775807)

    @model_validator(mode="after")
    def times(self):
        validate_time(self.interval_start)
        validate_time(self.interval_end)
        if not self.interval_start < self.interval_end:
            raise ValueError("invalid traffic interval")
        return self


class ResultInput(Strict):
    target_id: str = Field(max_length=36)
    started_at: datetime
    success: bool
    control_ok: bool
    latency_ms: float | None = Field(default=None, ge=0, le=60000)
    error_class: (
        Literal[
            "timeout",
            "connection_refused",
            "network_unreachable",
            "tls_failure",
            "dns_failure",
            "http_failure",
            "unknown",
        ]
        | None
    ) = None

    @field_validator("started_at")
    @classmethod
    def time(cls, value):
        return validate_time(value)


class BatchInput(Strict):
    batch_id: str = Field(min_length=16, max_length=80, pattern=r"^[A-Za-z0-9-]+$")
    sequence: int = Field(ge=0)
    schema_version: Literal[1, 2]
    created_at: float
    events: list[dict] = Field(min_length=1, max_length=1000)


class HeartbeatInput(Strict):
    agent_version: str | None = Field(default=None, max_length=40)
    hostname: str | None = Field(default=None, max_length=253)
    public_ipv4: str | None = None
    public_ipv6: str | None = None
    xray_version: str | None = Field(default=None, max_length=40)
    xray_running: bool | None = None
    spool_rows: int = Field(default=0, ge=0)
    spool_bytes: int = Field(default=0, ge=0)
    spool_capacity: int = Field(default=536870912, ge=1)
    spool_usage_ratio: float = Field(default=0, ge=0, le=1)
    oldest_batch: float | None = None
    last_upload: float | None = None
    evicted_batches: int = Field(default=0, ge=0)
    parser_errors: int = Field(default=0, ge=0)
    last_access_log_time: float | None = None

    @field_validator("public_ipv4", "public_ipv6")
    @classmethod
    def ip(cls, value, info):
        if value is not None:
            address = ipaddress.ip_address(value)
            expected = 4 if info.field_name == "public_ipv4" else 6
            if address.version != expected:
                raise ValueError("IP family mismatch")
            return str(address)
        return None


class EnrollInput(Strict):
    token: str = Field(min_length=20, max_length=256)
    name: str = Field(min_length=1, max_length=128)
    region: str = Field(default="", max_length=128)
    provider: str = Field(default="", max_length=128)


class TokenInput(Strict):
    kind: Literal["agents", "probes"]
    expires_minutes: int = Field(default=15, ge=1, le=1440)
    mainland: bool = False
    independence_group: str = Field(default="", max_length=128)
    vps_id: str | None = Field(default=None, max_length=36)


class LoginInput(Strict):
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)


class IdentityPatch(Strict):
    name: str = Field(min_length=1, max_length=128)
    region: str = Field(default="", max_length=128)
    independence_group: str = Field(default="", max_length=128)
    mainland: bool = False
    enabled: bool = True


class TargetPatch(Strict):
    enabled: bool


class AdminInput(LoginInput):
    role: Literal["admin", "viewer"] = "viewer"


class AdminPatch(Strict):
    role: Literal["admin", "viewer"]
    enabled: bool
    password: str | None = Field(default=None, min_length=14, max_length=256)


class PasswordInput(Strict):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=14, max_length=256)


class TargetInput(Strict):
    vps_id: str = Field(max_length=36)
    address: str
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "tls", "http", "https"] = "tcp"
    server_name: str | None = Field(default=None, max_length=253)
    path: str = Field(default="/", max_length=256, pattern=r"^/[^\r\n]*$")
    enabled: bool = True

    @field_validator("address")
    @classmethod
    def public_ip(cls, value):
        value = normalize_ip(value)
        if not ipaddress.ip_address(value).is_global:
            raise ValueError("probe targets require global addresses")
        return value

    @field_validator("server_name")
    @classmethod
    def host(cls, value):
        return normalize_domain(value) if value else None


class ManualInput(Strict):
    vps_id: str = Field(max_length=36)
    target_ip: str
    target_port: int | None = Field(default=None, ge=1, le=65535)
    first_known_bad_at: datetime
    last_known_good_at: datetime | None = None
    lookback_minutes: Literal[15, 30, 60, 180, 360, 1440] = 60
    notes: str = Field(default="", max_length=2000)

    @field_validator("target_ip")
    @classmethod
    def ip(cls, value):
        return normalize_ip(value)

    @model_validator(mode="after")
    def times(self):
        validate_time(self.first_known_bad_at)
        if self.last_known_good_at is not None:
            validate_time(self.last_known_good_at)
            if self.last_known_good_at > self.first_known_bad_at:
                raise ValueError("last good must precede first bad")
        return self
