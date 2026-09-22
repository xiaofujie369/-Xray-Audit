import csv
import hashlib
import io
import ipaddress
import json
import os
import secrets
import zlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import redis
from argon2.exceptions import VerificationError
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import String, cast, delete, func, insert, or_, select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from . import schemas as S
from .ai_review import Options as AIOptions
from .ai_review import configured as ai_configured
from .ai_review import options as ai_options
from .baseline import accumulate
from .db import Session, engine, now, query_lock, query_metrics, session, utc
from .metrics import increment
from .models import (
    VPS,
    Admin,
    AIReport,
    Batch,
    BlockEvent,
    Correlation,
    Enrollment,
    Event,
    Identity,
    InvestigationSnapshot,
    IPHistory,
    Job,
    LoginSession,
    ProbeResult,
    Setting,
    Target,
    Traffic,
)
from .queries import activity_summary
from .security import admin, agent, audit, bootstrap, current_user, digest, issue_session, passwords
from .settings import DEFAULTS, control_revision, settings

cache = redis.Redis.from_url(
    os.environ.get("REDIS_URL", "redis://localhost:6379/0"), socket_connect_timeout=0.2, socket_timeout=0.2
)


@asynccontextmanager
async def lifespan(app):
    if os.environ.get("APP_ENV", "production") == "production":
        if engine.dialect.name != "postgresql" or len(os.environ.get("APP_SECRET", "")) < 32:
            raise RuntimeError("production requires PostgreSQL and APP_SECRET of at least 32 characters")
        if not os.environ.get("PUBLIC_URL", "").startswith("https://"):
            raise RuntimeError("production requires HTTPS PUBLIC_URL")
    with Session() as db:
        bootstrap(db)
    yield


app = FastAPI(title="XBoard Audit Correlation", lifespan=lifespan, docs_url=None, redoc_url=None)


@app.exception_handler(SQLAlchemyError)
async def database_error(request, error):
    return JSONResponse({"detail": "database unavailable; batch was not acknowledged"}, status_code=503)


@app.exception_handler(RequestValidationError)
async def input_error(request, error):
    # FastAPI's default errors may echo passwords or unexpected payload fields.
    return JSONResponse({"detail": "invalid request"}, status_code=422)


class BodyLimit:
    def __init__(self, app):
        self.application = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.application(scope, receive, send)
        headers = dict(scope["headers"])
        compressed = 0
        chunks = bytearray()
        encoding = headers.get(b"content-encoding", b"")
        if encoding not in (b"", b"gzip", b"identity"):
            return await JSONResponse({"detail": "unsupported encoding"}, 415)(scope, receive, send)
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == b"gzip" else None
        try:
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                raw = message.get("body", b"")
                compressed += len(raw)
                if compressed > 1048576:
                    raise ValueError()
                chunks.extend(decoder.decompress(raw, 4194305 - len(chunks)) if decoder else raw)
                if len(chunks) > 4194304 or (decoder and decoder.unconsumed_tail):
                    raise ValueError()
                if not message.get("more_body"):
                    break
            if decoder and (not decoder.eof or decoder.unused_data):
                raise ValueError()
        except (ValueError, zlib.error):
            return await JSONResponse({"detail": "invalid or oversized body"}, 413)(scope, receive, send)
        scope["headers"] = [
            (k, v) for k, v in scope["headers"] if k not in (b"content-encoding", b"content-length")
        ]
        scope["headers"].append((b"content-length", str(len(chunks)).encode()))
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(chunks), "more_body": False}
            return await receive()

        await self.application(scope, replay, send)


app.add_middleware(BodyLimit)


@app.middleware("http")
async def headers(request, call_next):
    response = await call_next(request)
    response.headers.update(
        {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        }
    )
    return response


def rate_limit(key, maximum, required=False):
    try:
        count = cache.incr("rate:" + digest(key))
        if count == 1:
            cache.expire("rate:" + digest(key), 60)
        if count > maximum:
            raise HTTPException(429, "rate limit exceeded")
    except redis.RedisError:
        if required:
            raise HTTPException(503, "authentication rate limiter unavailable")


def row_dict(row):
    return {
        column.name: getattr(row, column.name)
        for column in row.__table__.columns
        if column.name not in ("token_hash", "password_hash", "csrf_hash")
    }


def page(db, query, page=1, size=50):
    rows = db.scalars(query.offset((page - 1) * size).limit(size + 1)).all()
    return {"items": [row_dict(x) for x in rows[:size]], "page": page, "has_more": len(rows) > size}


def time_range(start=None, end=None, max_days=31):
    end = end or now()
    start = start or end - timedelta(hours=24)
    if start.tzinfo is None or end.tzinfo is None or start >= end or end - start > timedelta(days=max_days):
        raise HTTPException(422, "invalid or excessive time range")
    return start, end


@app.post("/api/v1/auth/login")
def login(body: S.LoginInput, request: Request, response: Response, db=Depends(session)):
    rate_limit("login:" + request.client.host, 20, required=True)
    rate_limit("account:" + body.email.lower(), 10, required=True)
    user = db.scalar(select(Admin).where(Admin.email == body.email.lower()))
    try:
        if user is None or not user.enabled:
            # Run the same expensive KDF to avoid a cheap account enumeration oracle.
            passwords.hash(body.password)
            raise HTTPException(401, "invalid credentials")
        passwords.verify(user.password_hash, body.password)
    except VerificationError:
        audit(db, "anonymous", "login_failed")
        db.commit()
        raise HTTPException(401, "invalid credentials")
    result = issue_session(db, user, response)
    audit(db, user.email, "login")
    db.commit()
    return result


@app.post("/api/v1/auth/logout")
def logout(request: Request, response: Response, user=Depends(current_user), db=Depends(session)):
    db.execute(
        delete(LoginSession).where(
            LoginSession.token_hash == digest(request.cookies.get("audit_session", ""))
        )
    )
    audit(db, user.email, "logout")
    db.commit()
    response.delete_cookie("audit_session")
    response.delete_cookie("audit_csrf")
    return {"ok": True}


@app.post("/api/v1/auth/refresh")
def refresh(request: Request, response: Response, user=Depends(current_user), db=Depends(session)):
    db.execute(
        delete(LoginSession).where(
            LoginSession.token_hash == digest(request.cookies.get("audit_session", ""))
        )
    )
    result = issue_session(db, user, response)
    db.commit()
    return result


@app.get("/api/v1/auth/me")
def me(user=Depends(current_user)):
    return {"email": user.email, "role": user.role}


@app.post("/api/v1/admin-users")
def add_admin(body: S.AdminInput, user=Depends(admin), db=Depends(session)):
    if len(body.password) < 14:
        raise HTTPException(422, "password must contain at least 14 characters")
    item = Admin(email=body.email.lower(), password_hash=passwords.hash(body.password), role=body.role)
    db.add(item)
    audit(db, user.email, "create_user", email=body.email, role=body.role)
    db.commit()
    return row_dict(item)


@app.post("/api/v1/enrollment-tokens")
def create_token(body: S.TokenInput, user=Depends(admin), db=Depends(session)):
    if body.vps_id and (body.kind != "agents" or db.get(VPS, body.vps_id) is None):
        raise HTTPException(422, "unknown VPS for credential rotation")
    token = secrets.token_urlsafe(48)
    expires = now() + timedelta(minutes=body.expires_minutes)
    db.add(
        Enrollment(
            token_hash=digest(token),
            kind=body.kind,
            expires_at=expires,
            options={
                "mainland": body.mainland,
                "independence_group": body.independence_group,
                "vps_id": body.vps_id,
            },
        )
    )
    audit(db, user.email, "create_enrollment_token", kind=body.kind)
    db.commit()
    return {"token": token, "expires_at": expires, "kind": body.kind}


@app.post("/api/v1/auth/password")
def change_password(body: S.PasswordInput, user=Depends(current_user), db=Depends(session)):
    rate_limit("password:" + user.id, 5, required=True)
    try:
        passwords.verify(user.password_hash, body.current_password)
    except VerificationError:
        raise HTTPException(403, "current password incorrect")
    user.password_hash = passwords.hash(body.new_password)
    db.execute(delete(LoginSession).where(LoginSession.admin_id == user.id))
    audit(db, user.email, "change_password")
    db.commit()
    return {"ok": True, "login_required": True}


@app.get("/api/v1/admin-users")
def list_admins(
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user=Depends(admin),
    db=Depends(session),
):
    return page(db, select(Admin).order_by(Admin.email), page_number, size)


@app.patch("/api/v1/admin-users/{admin_id}")
def edit_admin(admin_id: str, body: S.AdminPatch, user=Depends(admin), db=Depends(session)):
    # Lock all enabled administrators to prevent concurrent removal of the last one.
    administrators = list(
        db.scalars(
            select(Admin)
            .where(Admin.enabled.is_(True), Admin.role == "admin")
            .order_by(Admin.id)
            .with_for_update()
        )
    )
    item = db.get(Admin, admin_id)
    if item is None:
        raise HTTPException(404)
    if (
        item.enabled
        and item.role == "admin"
        and (not body.enabled or body.role != "admin")
        and len(administrators) <= 1
    ):
        raise HTTPException(409, "cannot disable or demote the last administrator")
    item.role, item.enabled = body.role, body.enabled
    if body.password:
        item.password_hash = passwords.hash(body.password)
    db.execute(delete(LoginSession).where(LoginSession.admin_id == item.id))
    audit(
        db,
        user.email,
        "edit_admin",
        id=item.id,
        role=item.role,
        enabled=item.enabled,
        password_changed=bool(body.password),
    )
    db.commit()
    return row_dict(item)


@app.post("/api/v1/{kind}/enroll")
def enroll(kind: str, body: S.EnrollInput, request: Request, db=Depends(session)):
    if kind not in ("agents", "probes"):
        raise HTTPException(404)
    rate_limit("enroll:" + request.client.host, 10, required=True)
    token = db.scalar(select(Enrollment).where(Enrollment.token_hash == digest(body.token)).with_for_update())
    if token is None or token.kind != kind or token.used_at or utc(token.expires_at) <= now():
        raise HTTPException(401, "invalid or expired enrollment token")
    consumed = db.execute(
        update(Enrollment)
        .where(Enrollment.token_hash == digest(body.token), Enrollment.used_at.is_(None))
        .values(used_at=now())
    )
    if consumed.rowcount != 1:
        raise HTTPException(409, "enrollment already consumed")
    secret = secrets.token_urlsafe(48)
    vps = None
    identity = None
    if kind == "agents":
        if token.options.get("vps_id"):
            vps = db.scalar(select(VPS).where(VPS.id == token.options["vps_id"]).with_for_update())
            identity = db.scalar(
                select(Identity)
                .where(Identity.vps_id == vps.id, Identity.kind == kind)
                .order_by(Identity.created_at.desc())
                .limit(1)
            )
        else:
            vps = VPS(name=body.name, region=body.region, provider=body.provider)
            db.add(vps)
            db.flush()
    if identity is None:
        identity = Identity(
            kind=kind,
            vps_id=vps.id if vps else None,
            mainland=token.options.get("mainland", False),
            independence_group=token.options.get("independence_group", ""),
        )
    # Keep the batch deduplication namespace stable across credential rotation.
    identity.token_hash = digest(secret)
    identity.name = body.name
    identity.region = body.region
    identity.enabled = True
    db.add(identity)
    db.flush()
    audit(db, identity.id, "enrollment", kind=kind)
    db.commit()
    return {"id": identity.id, "token": secret, "vps_id": identity.vps_id}


@app.post("/api/v1/{kind}/heartbeat")
def heartbeat(kind: str, body: S.HeartbeatInput, identity=Depends(agent), db=Depends(session)):
    body = body.model_dump(exclude_none=True)
    allowed = {
        "agent_version",
        "hostname",
        "public_ipv4",
        "public_ipv6",
        "xray_version",
        "xray_running",
        "spool_rows",
        "spool_bytes",
        "spool_capacity",
        "spool_usage_ratio",
        "oldest_batch",
        "last_upload",
        "evicted_batches",
        "parser_errors",
        "last_access_log_time",
    }
    if set(body) - allowed or len(json.dumps(body)) > 8192:
        raise HTTPException(422, "invalid heartbeat")
    identity.last_heartbeat_at = now()
    if identity.vps_id:
        vps = db.get(VPS, identity.vps_id)
        vps.last_heartbeat_at = now()
        vps.health = body
        for key in ("agent_version", "hostname", "xray_version"):
            if key in body:
                if not isinstance(body[key], str) or len(body[key]) > (253 if key == "hostname" else 40):
                    raise HTTPException(422, "invalid version or hostname")
                setattr(vps, key, body[key])
        for key in ("public_ipv4", "public_ipv6"):
            if body.get(key):
                try:
                    address = ipaddress.ip_address(body[key])
                except ValueError:
                    raise HTTPException(422, "invalid IP")
                old = db.scalars(
                    select(IPHistory).where(
                        IPHistory.vps_id == vps.id,
                        IPHistory.family == address.version,
                        IPHistory.current.is_(True),
                    )
                ).all()
                if any(str(row.address) == str(address) for row in old):
                    for row in old:
                        row.last_seen = now()
                else:
                    for row in old:
                        row.current = False
                        row.last_seen = now()
                        for target in db.scalars(
                            select(Target).where(
                                Target.vps_id == vps.id,
                                Target.address == row.address,
                                Target.enabled.is_(True),
                            )
                        ):
                            target.enabled = False
                            existing = db.scalar(
                                select(Target).where(
                                    Target.vps_id == vps.id,
                                    Target.address == str(address),
                                    Target.port == target.port,
                                    Target.protocol == target.protocol,
                                )
                            )
                            if existing:
                                existing.enabled = True
                            else:
                                db.add(
                                    Target(
                                        vps_id=vps.id,
                                        address=str(address),
                                        port=target.port,
                                        protocol=target.protocol,
                                        server_name=target.server_name,
                                        path=target.path,
                                    )
                                )
                    db.add(IPHistory(vps_id=vps.id, address=str(address), family=address.version))
    db.commit()
    return {"ok": True}


@app.get("/api/v1/{kind}/config")
def agent_config(kind: str, identity=Depends(agent), db=Depends(session)):
    config = settings(db)
    if kind == "probes":
        targets = db.scalars(select(Target).where(Target.enabled.is_(True)).limit(2000)).all()
        return {
            "targets": [row_dict(x) for x in targets],
            "controls": config["control_targets"],
            "control_revision": control_revision(config["control_targets"]),
            "interval": config["probe_interval_seconds"],
        }
    return {"schema_versions": [1, 2], "latest_version": "2.1.0-dev", "max_events": 1000}


@app.post("/api/v1/{kind}/{collection}/batch")
def ingest(kind: str, collection: str, body: S.BatchInput, identity=Depends(agent), db=Depends(session)):
    mapping = {
        ("agents", "events"): (S.EventInput, Event),
        ("agents", "traffic"): (S.TrafficInput, Traffic),
        ("probes", "results"): (S.ResultInput, ProbeResult),
    }
    if (kind, collection) not in mapping:
        raise HTTPException(404)
    rate_limit("ingest:" + identity.id, 600)
    checksum = hashlib.sha256(body.model_dump_json().encode()).hexdigest()
    old = db.get(Batch, (identity.id, body.batch_id))
    if old:
        if old.body_hash != checksum or old.kind != collection:
            raise HTTPException(409, "batch ID reused for different content")
        increment(db, "audit_ingest_duplicates_total")
        db.commit()
        return {"accepted": True, "batch_id": body.batch_id, "duplicate": True}
    validator, model = mapping[(kind, collection)]
    try:
        rows = [validator.model_validate(row).model_dump() for row in body.events]
    except ValidationError:
        raise HTTPException(422, "invalid batch events")
    try:
        db.add(Batch(agent_id=identity.id, batch_id=body.batch_id, kind=collection, body_hash=checksum))
        db.flush()
        if model is ProbeResult:
            targets = set(db.scalars(select(Target.id)))
            if any(row["target_id"] not in targets for row in rows):
                raise HTTPException(422, "unknown probe target")
            for row in rows:
                row["probe_id"] = identity.id
            db.execute(insert(model), rows)
            for target in {row["target_id"] for row in rows}:
                db.add(Job(kind="transition", payload={"id": target}))
            increment(db, "audit_probe_success_total", sum(row["success"] for row in rows))
            increment(db, "audit_probe_failure_total", sum(not row["success"] for row in rows))
        else:
            for row in rows:
                row["vps_id"] = identity.vps_id
            db.execute(insert(model), rows)
        increment(db, "audit_ingest_batches_total")
        if model is Event:
            increment(db, "audit_ingest_events_total", len(rows))
            accumulate(db, rows)
            if rows:
                first = min(row["bucket_start"] for row in rows)
                last = max(row["bucket_start"] for row in rows)
                db.execute(update(BlockEvent).where(
                    BlockEvent.vps_id == identity.vps_id,
                    BlockEvent.window_end > first,
                    BlockEvent.window_end <= last + timedelta(days=8),
                ).values(investigation_dirty=True))
        db.commit()
    except IntegrityError:
        db.rollback()
        old = db.get(Batch, (identity.id, body.batch_id))
        if old is None or old.body_hash != checksum:
            raise HTTPException(409, "batch conflict")
    return {"accepted": True, "batch_id": body.batch_id}


@app.get("/api/v1/vps")
def list_vps(
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    region: str | None = None,
    provider: str | None = None,
    user=Depends(current_user),
    db=Depends(session),
):
    query = select(VPS).order_by(VPS.name)
    if region:
        query = query.where(VPS.region == region)
    if provider:
        query = query.where(VPS.provider == provider)
    result = page(db, query, page_number, size)
    for item in result["items"]:
        item["status"] = (
            "online"
            if item["last_heartbeat_at"] and utc(item["last_heartbeat_at"]) >= now() - timedelta(minutes=3)
            else "offline"
        )
        item["current_ip"] = list(
            db.scalars(
                select(IPHistory.address).where(IPHistory.vps_id == item["id"], IPHistory.current.is_(True))
            )
        )
        latest = db.scalar(
            select(BlockEvent)
            .where(BlockEvent.vps_id == item["id"])
            .order_by(BlockEvent.detected_at.desc())
            .limit(1)
        )
        active = db.scalar(
            select(BlockEvent.state)
            .where(BlockEvent.vps_id == item["id"], BlockEvent.state.in_(["confirmed", "suspected"]))
            .order_by(BlockEvent.state)
            .limit(1)
        )
        item["reachability"] = active or (latest.state if latest else "unknown")
        if not active:
            config = settings(db)
            targets = list(
                db.scalars(select(Target.id).where(Target.vps_id == item["id"], Target.enabled.is_(True)))
            )
            normal = bool(targets)
            for target_id in targets:
                rows = db.execute(
                    select(
                        Identity.independence_group,
                        Identity.id,
                        ProbeResult.success,
                        ProbeResult.control_ok,
                        ProbeResult.started_at,
                    )
                    .join(ProbeResult, ProbeResult.probe_id == Identity.id)
                    .where(
                        ProbeResult.target_id == target_id,
                        Identity.enabled.is_(True),
                        Identity.mainland.is_(True),
                        ProbeResult.started_at
                        >= now() - timedelta(seconds=config["probe_interval_seconds"] * 3),
                    )
                    .order_by(ProbeResult.started_at.desc())
                    .limit(2000)
                )
                seen, groups = set(), set()
                for group, probe_id, success, control, stamp in rows:
                    if probe_id in seen:
                        continue
                    seen.add(probe_id)
                    if success and control:
                        groups.add(group or probe_id)
                normal = normal and len(groups) >= config["min_distinct_probes"]
            if normal:
                item["reachability"] = "recovered" if latest and latest.state == "recovered" else "normal"
    return result


@app.get("/api/v1/vps/{vps_id}")
def vps_detail(vps_id: str, user=Depends(current_user), db=Depends(session)):
    vps = db.get(VPS, vps_id)
    if vps is None:
        raise HTTPException(404)
    result = row_dict(vps)
    result["ip_history"] = [
        row_dict(x)
        for x in db.scalars(
            select(IPHistory)
            .where(IPHistory.vps_id == vps_id)
            .order_by(IPHistory.last_seen.desc())
            .limit(100)
        )
    ]
    result["targets"] = [
        row_dict(x) for x in db.scalars(select(Target).where(Target.vps_id == vps_id).limit(200))
    ]
    result["activity_24h"] = activity_summary(
        db, [Event.vps_id == vps_id, Event.bucket_start >= now() - timedelta(days=1)]
    )
    result["recent_incidents"] = [
        row_dict(x)
        for x in db.scalars(
            select(BlockEvent)
            .where(BlockEvent.vps_id == vps_id)
            .order_by(BlockEvent.detected_at.desc())
            .limit(20)
        )
    ]
    return result


@app.patch("/api/v1/vps/{vps_id}")
def edit_vps(vps_id: str, body: dict, user=Depends(admin), db=Depends(session)):
    vps = db.get(VPS, vps_id)
    if not vps:
        raise HTTPException(404)
    if set(body) - {"name", "region", "provider"} or any(
        not isinstance(v, str) or len(v) > 128 for v in body.values()
    ):
        raise HTTPException(422)
    for key, value in body.items():
        setattr(vps, key, value)
    audit(db, user.email, "edit_vps", id=vps_id)
    db.commit()
    return row_dict(vps)


@app.get("/api/v1/identities")
def identities(
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user=Depends(admin),
    db=Depends(session),
):
    return page(db, select(Identity).order_by(Identity.created_at.desc()), page_number, size)


@app.delete("/api/v1/identities/{identity_id}")
def revoke(identity_id: str, user=Depends(admin), db=Depends(session)):
    item = db.get(Identity, identity_id)
    if item is None:
        raise HTTPException(404)
    item.enabled = False
    audit(db, user.email, "revoke_identity", id=item.id)
    db.commit()
    return {"ok": True}


@app.patch("/api/v1/identities/{identity_id}")
def edit_identity(identity_id: str, body: S.IdentityPatch, user=Depends(admin), db=Depends(session)):
    item = db.get(Identity, identity_id)
    if item is None:
        raise HTTPException(404)
    for key, value in body.model_dump().items():
        setattr(item, key, value)
    audit(db, user.email, "edit_identity", id=item.id)
    db.commit()
    return row_dict(item)


@app.get("/api/v1/probe-targets")
def targets(
    vps_id: str | None = None,
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user=Depends(current_user),
    db=Depends(session),
):
    query = select(Target).order_by(Target.vps_id, Target.address, Target.port)
    if vps_id:
        query = query.where(Target.vps_id == vps_id)
    return page(db, query, page_number, size)


@app.patch("/api/v1/probe-targets/{target_id}")
def edit_target(target_id: str, body: S.TargetPatch, user=Depends(admin), db=Depends(session)):
    item = db.get(Target, target_id)
    if item is None:
        raise HTTPException(404)
    item.enabled = body.enabled
    audit(db, user.email, "edit_probe_target", id=item.id, enabled=item.enabled)
    db.commit()
    return row_dict(item)


@app.post("/api/v1/probe-targets")
def add_target(body: S.TargetInput, user=Depends(admin), db=Depends(session)):
    if db.get(VPS, body.vps_id) is None:
        raise HTTPException(404)
    item = Target(**body.model_dump())
    if db.scalar(
        select(Target.id).where(
            Target.vps_id == body.vps_id,
            Target.address == body.address,
            Target.port == body.port,
            Target.protocol == body.protocol,
        )
    ):
        raise HTTPException(409, "target already exists; enable the existing target")
    db.add(item)
    audit(db, user.email, "create_probe_target", vps_id=body.vps_id)
    db.commit()
    return row_dict(item)


@app.get("/api/v1/probe-results")
def probe_results(
    target_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user=Depends(current_user),
    db=Depends(session),
):
    start, end = time_range(start, end)
    query = select(ProbeResult).where(ProbeResult.started_at >= start, ProbeResult.started_at < end)
    if target_id:
        query = query.where(ProbeResult.target_id == target_id)
    return page(db, query.order_by(ProbeResult.started_at.desc(), ProbeResult.id.desc()), page_number, size)


def events_query(
    start, end, vps_id=None, user_id=None, source_ip=None, domain=None, destination_ip=None, node_id=None
):
    query = select(Event).where(Event.bucket_start >= start, Event.bucket_start < end)
    for field, value in (
        (Event.vps_id, vps_id),
        (Event.user_id, user_id),
        (Event.source_ip, source_ip),
        (Event.destination_domain, domain),
        (Event.destination_ip, destination_ip),
        (Event.node_id, node_id),
    ):
        if value is not None:
            query = query.where(field == value)
    return query.order_by(Event.bucket_start.desc(), Event.id.desc())


@app.get("/api/v1/events/summary")
def summary(user=Depends(current_user), db=Depends(session)):
    cutoff = now() - timedelta(hours=24)
    result = {
        "total_vps": db.scalar(select(func.count()).select_from(VPS)),
        "online_vps": db.scalar(
            select(func.count()).select_from(VPS).where(VPS.last_heartbeat_at >= now() - timedelta(minutes=3))
        ),
        "connections_24h": db.scalar(
            select(func.coalesce(func.sum(Event.connections), 0)).where(Event.bucket_start >= cutoff)
        ),
        "users_24h": db.scalar(
            select(func.count(func.distinct(Event.user_id))).where(Event.bucket_start >= cutoff)
        ),
        "states": dict(db.execute(select(BlockEvent.state, func.count()).group_by(BlockEvent.state)).all()),
    }
    result["offline_vps"] = result["total_vps"] - result["online_vps"]
    result["recovered_24h"] = db.scalar(
        select(func.count()).select_from(BlockEvent).where(BlockEvent.recovered_at >= cutoff)
    )
    result["events_24h"] = db.scalar(
        select(func.count()).select_from(Event).where(Event.bucket_start >= cutoff)
    )
    day = func.substr(cast(BlockEvent.detected_at, String), 1, 10)
    result["charts"] = {
        "incidents": [
            dict(label=label, value=value)
            for label, value in db.execute(
                select(day, func.count())
                .where(BlockEvent.detected_at >= now() - timedelta(days=30))
                .group_by(day)
                .order_by(day)
            )
        ],
        "vps": [
            dict(label=label, value=value)
            for label, value in db.execute(
                select(VPS.name, func.sum(Event.connections))
                .join(Event, Event.vps_id == VPS.id)
                .where(Event.bucket_start >= cutoff)
                .group_by(VPS.id, VPS.name)
                .order_by(func.sum(Event.connections).desc())
                .limit(10)
            )
        ],
    }
    for kind in ("domain", "user", "source_ip"):
        score = func.max(Correlation.score)
        result["charts"][kind] = [
            dict(label=label, value=value)
            for label, value in db.execute(
                select(Correlation.entity_key, score)
                .where(Correlation.entity_type == kind)
                .group_by(Correlation.entity_key)
                .order_by(score.desc())
                .limit(10)
            )
        ]
    return result


@app.get("/api/v1/events")
def events(
    start: datetime | None = None,
    end: datetime | None = None,
    vps_id: str | None = None,
    user_id: int | None = None,
    source_ip: str | None = None,
    domain: str | None = None,
    destination_ip: str | None = None,
    node_id: int | None = None,
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user=Depends(current_user),
    db=Depends(session),
):
    start, end = time_range(start, end)
    for ip in (source_ip, destination_ip):
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise HTTPException(422, "invalid IP")
    return page(
        db,
        events_query(start, end, vps_id, user_id, source_ip, domain, destination_ip, node_id),
        page_number,
        size,
    )


@app.get("/api/v1/search")
def search(
    q: str = Query(min_length=1, max_length=253),
    start: datetime | None = None,
    end: datetime | None = None,
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user=Depends(current_user),
    db=Depends(session),
):
    start, end = time_range(start, end)
    filters = [
        Event.destination_domain == q.lower().rstrip("."),
        Event.vps_id == q,
        Event.vps_id.in_(select(VPS.id).where(VPS.name == q)),
    ]
    if q.isdecimal():
        filters.extend([Event.user_id == int(q), Event.node_id == int(q)])
    try:
        ip = str(ipaddress.ip_address(q))
        filters.extend([Event.source_ip == ip, Event.destination_ip == ip])
    except ValueError:
        pass
    query = (
        select(Event)
        .where(Event.bucket_start >= start, Event.bucket_start < end, or_(*filters))
        .order_by(Event.bucket_start.desc(), Event.id.desc())
    )
    return page(db, query, page_number, size)


@app.get("/api/v1/{entity}/{key}/activity")
def activity(
    entity: str,
    key: str,
    start: datetime | None = None,
    end: datetime | None = None,
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user=Depends(current_user),
    db=Depends(session),
):
    mapping = {
        "users": "user_id",
        "source-ips": "source_ip",
        "domains": "domain",
        "destination-ips": "destination_ip",
    }
    if entity not in mapping:
        raise HTTPException(404)
    start, end = time_range(start, end)
    value = key
    if entity == "users":
        if not key.isdecimal():
            raise HTTPException(422)
        value = int(key)
    return page(db, events_query(start, end, **{mapping[entity]: value}), page_number, size)


@app.get("/api/v1/traffic")
def traffic(
    vps_id: str | None = None,
    user_id: int | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user=Depends(current_user),
    db=Depends(session),
):
    start, end = time_range(start, end)
    query = select(Traffic).where(Traffic.interval_start >= start, Traffic.interval_start < end)
    if vps_id:
        query = query.where(Traffic.vps_id == vps_id)
    if user_id is not None:
        query = query.where(Traffic.user_id == user_id)
    return page(db, query.order_by(Traffic.interval_start.desc(), Traffic.id.desc()), page_number, size)


@app.get("/api/v1/block-events")
def incidents(
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    vps_id: str | None = None,
    state: str | None = None,
    user=Depends(current_user),
    db=Depends(session),
):
    query = select(BlockEvent).order_by(BlockEvent.detected_at.desc())
    if vps_id:
        query = query.where(BlockEvent.vps_id == vps_id)
    if state:
        query = query.where(BlockEvent.state == state)
    return page(db, query, page_number, size)


@app.post("/api/v1/block-events")
def manual_incident(body: S.ManualInput, user=Depends(admin), db=Depends(session)):
    if not db.get(VPS, body.vps_id):
        raise HTTPException(404)
    item = BlockEvent(
        **body.model_dump(exclude={"lookback_minutes"}),
        state="manual",
        source="manual",
        window_end=body.first_known_bad_at,
        window_start=body.first_known_bad_at - timedelta(minutes=body.lookback_minutes),
    )
    db.add(item)
    db.flush()
    db.add(Job(kind="correlate", payload={"id": item.id}))
    audit(db, user.email, "manual_incident", id=item.id)
    db.commit()
    return row_dict(item)


@app.get("/api/v1/block-events/{event_id}")
def incident_detail(event_id: str, user=Depends(current_user), db=Depends(session)):
    item = db.get(BlockEvent, event_id)
    if item is None:
        raise HTTPException(404)
    result = row_dict(item)
    result["activity"] = activity_summary(
        db,
        [
            Event.vps_id == item.vps_id,
            Event.bucket_start >= item.window_start,
            Event.bucket_start < item.window_end,
        ],
    )
    traffic_rows = db.execute(
        select(Traffic.user_id, func.sum(Traffic.uplink_bytes), func.sum(Traffic.downlink_bytes))
        .where(
            Traffic.vps_id == item.vps_id,
            Traffic.interval_start >= item.window_start,
            Traffic.interval_end <= item.window_end,
        )
        .group_by(Traffic.user_id)
        .order_by(func.sum(Traffic.uplink_bytes + Traffic.downlink_bytes).desc())
        .limit(50)
    )
    result["user_traffic"] = [
        dict(user_id=key, uplink_bytes=up, downlink_bytes=down) for key, up, down in traffic_rows
    ]
    return result


@app.get("/api/v1/block-events/{event_id}/investigation")
def investigation_detail(event_id: str, snapshot_id: str | None = None, user=Depends(current_user), db=Depends(session)):
    if db.get(BlockEvent, event_id) is None:
        raise HTTPException(404, "incident not found")
    query = select(InvestigationSnapshot).where(InvestigationSnapshot.block_event_id == event_id)
    if snapshot_id:
        query = query.where(InvestigationSnapshot.id == snapshot_id)
    snapshot = db.scalar(query.order_by(InvestigationSnapshot.created_at.desc(), InvestigationSnapshot.id.desc()).limit(1))
    if snapshot is None:
        return {"status": "pending", "detail": "Investigation snapshot has not been captured yet."}
    return {"status": "ready", "id": snapshot.id, "created_at": snapshot.created_at,
            "content_hash": snapshot.content_hash, "evidence": snapshot.payload}


@app.get("/api/v1/ai/settings")
def ai_configuration(user=Depends(current_user), db=Depends(session)):
    usage = db.get(Setting, "ai_daily_usage")
    today = now().date().isoformat()
    return {"options": ai_options(db).model_dump(), "configured": ai_configured(),
            "model": os.environ.get("AI_MODEL", ""), "usage_day_utc": today,
            "requests_today": usage.value.get("requests", 0) if usage and usage.value.get("day") == today else 0,
            "privacy": "Only pseudonyms, aggregate counts and probe outcomes leave this server. Read-only reports."}


@app.patch("/api/v1/ai/settings")
def change_ai_configuration(body: AIOptions, user=Depends(admin), db=Depends(session)):
    if body.enabled and not ai_configured():
        raise HTTPException(422, "Configure HTTPS AI_API_URL, AI_API_KEY and AI_MODEL in the central .env first")
    db.merge(Setting(key="ai_options", value=body.model_dump()))
    audit(db, user.email, "change_ai_options", enabled=body.enabled)
    db.commit()
    return ai_configuration(user, db)


@app.get("/api/v1/block-events/{event_id}/ai-reports")
def incident_reports(event_id: str, user=Depends(current_user), db=Depends(session)):
    if db.get(BlockEvent, event_id) is None:
        raise HTTPException(404, "incident not found")
    rows = db.scalars(select(AIReport).join(InvestigationSnapshot).where(
        InvestigationSnapshot.block_event_id == event_id
    ).order_by(AIReport.created_at.desc()).limit(20)).all()
    return {"items": [{key: value for key, value in row_dict(row).items() if key != "lease_token"}
                      for row in rows]}


@app.post("/api/v1/ai/reports/{report_id}/retry")
def retry_ai_report(report_id: str, user=Depends(admin), db=Depends(session)):
    report = db.scalar(select(AIReport).where(AIReport.id == report_id).with_for_update())
    if report is None:
        raise HTTPException(404, "report not found")
    if report.status != "failed":
        raise HTTPException(409, "only failed reports can be retried")
    report.status, report.attempts, report.available_at = "pending", 0, now()
    report.error_code = None
    audit(db, user.email, "retry_ai_report", report_id=report_id)
    db.commit()
    return {"ok": True}


@app.post("/api/v1/block-events/{event_id}/recalculate")
def recalculate(event_id: str, user=Depends(admin), db=Depends(session)):
    if db.get(BlockEvent, event_id) is None:
        raise HTTPException(404)
    db.add(Job(kind="correlate", payload={"id": event_id}))
    audit(db, user.email, "recalculate", id=event_id)
    db.commit()
    return {"queued": True}


@app.get("/api/v1/correlation/{entity}")
def correlations(
    entity: str,
    event_id: str | None = None,
    key: str | None = None,
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user=Depends(current_user),
    db=Depends(session),
):
    mapping = {
        "users": "user",
        "source-ips": "source_ip",
        "domains": "domain",
        "destination-ips": "destination_ip",
        "nodes": "node",
    }
    if entity not in mapping:
        raise HTTPException(404)
    query = select(Correlation).where(Correlation.entity_type == mapping[entity])
    if event_id:
        query = query.where(Correlation.block_event_id == event_id)
    if key:
        query = query.where(Correlation.entity_key == key)
    result = page(db, query.order_by(Correlation.score.desc(), Correlation.id.desc()), page_number, size)
    incidents = {row.id: row for row in db.scalars(select(BlockEvent).where(
        BlockEvent.id.in_({item["block_event_id"] for item in result["items"]})
    ))}
    for item in result["items"]:
        incident = incidents.get(item["block_event_id"])
        if incident:
            item.update(vps_id=incident.vps_id, incident_state=incident.state,
                        incident_time=incident.first_known_bad_at)
    return result


@app.get("/api/v1/settings")
def get_settings(user=Depends(current_user), db=Depends(session)):
    return settings(db)


@app.patch("/api/v1/settings")
def edit_settings(body: dict, user=Depends(admin), db=Depends(session)):
    if set(body) - set(DEFAULTS):
        raise HTTPException(422)
    for key, value in body.items():
        limits = {
            "fail_consecutive": (1, 10),
            "recover_consecutive": (1, 10),
            "min_distinct_probes": (1, 20),
            "probe_interval_seconds": (30, 3600),
        }
        if key in limits and (type(value) is not int or not limits[key][0] <= value <= limits[key][1]):
            raise HTTPException(422, "setting outside supported bounds")
        if key == "lookback_minutes" and value not in (15, 30, 60, 180, 360, 1440):
            raise HTTPException(422, "invalid investigation window")
        if isinstance(DEFAULTS[key], int) and (type(value) is not int or not 1 <= value <= 3650):
            raise HTTPException(422)
        if key == "weights" and (
            not isinstance(value, list)
            or len(value) != 5
            or any(type(v) not in (float, int) or not 0 <= v <= 1 for v in value)
            or abs(sum(value) - 1) > 0.001
        ):
            raise HTTPException(422)
        if key == "domain_ignore" and (
            not isinstance(value, list)
            or len(value) > 1000
            or any(not isinstance(v, str) or len(v) > 253 for v in value)
        ):
            raise HTTPException(422)
        if key == "control_targets":
            if not isinstance(value, list) or len(value) > 10:
                raise HTTPException(422)
            try:
                for target in value:
                    if (
                        set(target) != {"address", "port"}
                        or not ipaddress.ip_address(target["address"]).is_global
                        or type(target["port"]) is not int
                        or not 1 <= target["port"] <= 65535
                    ):
                        raise ValueError()
            except (ValueError, KeyError, TypeError):
                raise HTTPException(422)
        if key == "timezone" and (not isinstance(value, str) or len(value) > 64):
            raise HTTPException(422)
        if key == "timezone" and value != "browser":
            try:
                ZoneInfo(value)
            except (ValueError, ZoneInfoNotFoundError):
                raise HTTPException(422, "invalid IANA timezone")
        db.merge(Setting(key=key, value=value))
    audit(db, user.email, "change_settings", keys=list(body))
    if {"weights", "domain_ignore"} & set(body):
        db.execute(update(BlockEvent).values(investigation_dirty=True))
    db.commit()
    return settings(db)


@app.get("/api/v1/export")
def export(start: datetime, end: datetime, user=Depends(admin), db=Depends(session)):
    start, end = time_range(start, end, max_days=int(os.environ.get("EXPORT_MAX_DAYS", "7")))
    limit = int(os.environ.get("EXPORT_MAX_ROWS", "100000"))
    rows = db.scalars(events_query(start, end).limit(limit + 1)).all()
    if len(rows) > limit:
        raise HTTPException(422, "reduce export range")
    output = io.StringIO()
    writer = csv.writer(output)
    columns = [
        "bucket_start",
        "vps_id",
        "node_id",
        "user_id",
        "source_ip",
        "destination_domain",
        "destination_ip",
        "destination_port",
        "connections",
    ]
    writer.writerow(columns)
    for row in rows:
        values = [str(getattr(row, k) or "") for k in columns]
        writer.writerow(
            ["'" + v if v.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else v for v in values]
        )
    audit(db, user.email, "export_data", start=start.isoformat(), end=end.isoformat(), rows=len(rows))
    db.commit()
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit.csv"},
    )


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/v1/entities/{entity}/{key}")
def entity_detail(
    entity: str,
    key: str,
    start: datetime | None = None,
    end: datetime | None = None,
    user=Depends(current_user),
    db=Depends(session),
):
    mapping = {
        "users": (Event.user_id, "user"),
        "source-ips": (Event.source_ip, "source_ip"),
        "domains": (Event.destination_domain, "domain"),
        "destination-ips": (Event.destination_ip, "destination_ip"),
    }
    if entity not in mapping:
        raise HTTPException(404)
    start, end = time_range(start, end)
    field, kind = mapping[entity]
    value = key
    if entity == "users":
        if not key.isdecimal() or int(key) > 9223372036854775807:
            raise HTTPException(422)
        value = int(key)
    if entity in ("source-ips", "destination-ips"):
        try:
            value = str(ipaddress.ip_address(key))
        except ValueError:
            raise HTTPException(422)
    result = activity_summary(db, [field == value, Event.bucket_start >= start, Event.bucket_start < end])
    result.update(entity=key, entity_type=kind, window_start=start, window_end=end)
    result["correlations"] = [
        row_dict(x)
        for x in db.scalars(
            select(Correlation)
            .where(Correlation.entity_type == kind, Correlation.entity_key == key)
            .order_by(Correlation.score.desc())
            .limit(50)
        )
    ]
    if entity == "users":
        traffic_rows = db.execute(
            select(Traffic.vps_id, func.sum(Traffic.uplink_bytes), func.sum(Traffic.downlink_bytes))
            .where(Traffic.user_id == value, Traffic.interval_start >= start, Traffic.interval_end <= end)
            .group_by(Traffic.vps_id)
            .limit(100)
        )
        result["user_traffic"] = [
            dict(vps_id=vps, uplink_bytes=up, downlink_bytes=down) for vps, up, down in traffic_rows
        ]
    return result


@app.get("/api/v1/admin-audit-log")
def admin_log(
    page_number: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user=Depends(admin),
    db=Depends(session),
):
    from .models import AuditLog

    return page(db, select(AuditLog).order_by(AuditLog.created_at.desc()), page_number, size)


@app.get("/readyz")
def readyz(db=Depends(session)):
    db.execute(text("SELECT 1"))
    return {"ok": True}


@app.get("/api/v1/system/health")
def system_health(user=Depends(current_user), db=Depends(session)):
    db.execute(text("SELECT 1"))
    try:
        redis_ok = cache.ping()
    except redis.RedisError:
        redis_ok = False
    size = (
        db.scalar(text("SELECT pg_database_size(current_database())"))
        if engine.dialect.name == "postgresql"
        else None
    )
    return {
        "database": True,
        "redis": redis_ok,
        "database_bytes": size,
        "pending_jobs": db.scalar(select(func.count()).select_from(Job)),
        "pending_ai_reports": db.scalar(select(func.count()).select_from(AIReport).where(AIReport.status.in_(["pending", "running"]))),
        "failed_ai_reports": db.scalar(select(func.count()).select_from(AIReport).where(AIReport.status == "failed")),
        "baseline_backfill": db.get(Setting, "baseline_backfill").value if db.get(Setting, "baseline_backfill") else None,
        "ai_worker_last_seen": db.get(Setting, "ai_worker_last_seen").value if db.get(Setting, "ai_worker_last_seen") else None,
        "version": "2.1.0-dev",
        "worker_last_seen": db.get(Setting, "worker_last_seen").value
        if db.get(Setting, "worker_last_seen")
        else None,
        "event_table_bytes": db.scalar(text("SELECT pg_total_relation_size('audit_events_1m')"))
        if db.bind.dialect.name == "postgresql"
        else None,
    }


@app.get("/metrics")
@app.get("/api/v1/system/metrics")
def metrics(user=Depends(current_user), db=Depends(session)):
    from .models import Counter

    values = {
        "audit_worker_queue_depth": db.scalar(select(func.count()).select_from(Job)),
        "audit_block_events_total": db.scalar(select(func.count()).select_from(BlockEvent)),
    }
    values.update({row.name: row.value for row in db.scalars(select(Counter))})
    with query_lock:
        values["audit_db_query_seconds_count"] = query_metrics["count"]
        values["audit_db_query_seconds_sum"] = query_metrics["seconds"]
    hosts = list(db.scalars(select(VPS)))
    values["audit_spool_bytes"] = sum((host.health or {}).get("spool_bytes", 0) for host in hosts)
    values["audit_spool_rows"] = sum((host.health or {}).get("spool_rows", 0) for host in hosts)
    values["audit_parser_errors_total"] = sum((host.health or {}).get("parser_errors", 0) for host in hosts)
    values["audit_agent_last_seen_seconds"] = max(
        ((now() - utc(host.last_heartbeat_at)).total_seconds() for host in hosts if host.last_heartbeat_at),
        default=0,
    )
    return Response("".join(f"{key} {value}\n" for key, value in values.items()), media_type="text/plain")
