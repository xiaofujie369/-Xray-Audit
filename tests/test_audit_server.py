import gzip
import os
from datetime import timedelta
from unittest.mock import patch

os.environ["APP_ENV"] = "test"
os.environ["ADMIN_EMAIL"] = "admin@example.test"
os.environ["ADMIN_PASSWORD"] = "test-only-password-123"

import pytest
from app.db import Base, now, session
from app.main import app
from app.models import Event
from app.security import bootstrap
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def client(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "test.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as db:
        bootstrap(db)

    def dependency():
        with factory() as db:
            yield db

    app.dependency_overrides[session] = dependency
    with patch("app.main.rate_limit"), patch("app.main.Session", factory):
        with TestClient(app) as client:
            client.db_factory = factory
            yield client
    app.dependency_overrides.clear()
    engine.dispose()


def login(client):
    response = client.post(
        "/api/v1/auth/login", json={"email": "admin@example.test", "password": "test-only-password-123"}
    )
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]


def enroll(client, kind="agents"):
    login(client)
    token = client.post("/api/v1/enrollment-tokens", json={"kind": kind}).json()["token"]
    response = client.post(f"/api/v1/{kind}/enroll", json={"token": token, "name": "test"})
    assert response.status_code == 200, response.text
    result = response.json()
    result["headers"] = {"Authorization": "Bearer " + result["token"], "X-Agent-ID": result["id"]}
    return token, result


def batch():
    stamp = now().replace(second=0, microsecond=0).isoformat()
    return {
        "batch_id": "0000000000001-abcdef",
        "sequence": 1,
        "schema_version": 2,
        "created_at": now().timestamp(),
        "events": [
            {
                "bucket_start": stamp,
                "bucket_seconds": 60,
                "first_seen": stamp,
                "last_seen": stamp,
                "connections": 3,
                "source_ip": "1.2.3.4",
                "destination_domain": "example.com",
                "destination_port": 443,
                "user_id": 12,
                "node_id": 3,
                "network": "tcp",
                "decision": "accepted",
            }
        ],
    }


def test_enrollment_is_one_use_and_scoped(client):
    token, identity = enroll(client)
    assert client.post("/api/v1/agents/enroll", json={"token": token, "name": "again"}).status_code == 401
    assert client.get("/api/v1/probes/config", headers=identity["headers"]).status_code == 403
    assert client.get("/api/v1/agents/config", headers=identity["headers"]).status_code == 200


def test_ai_configuration_requires_admin_and_never_returns_api_key(client):
    assert client.get("/api/v1/ai/settings").status_code == 401
    login(client)
    with patch.dict("os.environ", {"AI_API_URL": "https://example.test/chat/completions", "AI_API_KEY": "private-test-key", "AI_MODEL": "test-model"}):
        response = client.patch("/api/v1/ai/settings", json={"enabled": True, "daily_request_limit": 2})
        assert response.status_code == 200
        assert response.json()["configured"]
        assert "private-test-key" not in response.text
        client.post("/api/v1/admin-users", json={"email": "viewer@example.test", "password": "viewer-password-123456", "role": "viewer"})
        result = client.post("/api/v1/auth/login", json={"email": "viewer@example.test", "password": "viewer-password-123456"})
        client.headers["X-CSRF-Token"] = result.json()["csrf_token"]
        assert client.get("/api/v1/ai/settings").status_code == 200
        assert client.patch("/api/v1/ai/settings", json={"enabled": False}).status_code == 403


def test_rotation_preserves_dedupe_and_invalidates_old_token(client):
    _, identity = enroll(client)
    payload = batch()
    assert (
        client.post("/api/v1/agents/events/batch", json=payload, headers=identity["headers"]).status_code
        == 200
    )
    token = client.post(
        "/api/v1/enrollment-tokens", json={"kind": "agents", "vps_id": identity["vps_id"]}
    ).json()["token"]
    rotated = client.post("/api/v1/agents/enroll", json={"token": token, "name": "rotated"}).json()
    assert rotated["id"] == identity["id"]
    assert rotated["vps_id"] == identity["vps_id"]
    assert client.get("/api/v1/agents/config", headers=identity["headers"]).status_code == 401
    headers = {"Authorization": "Bearer " + rotated["token"], "X-Agent-ID": rotated["id"]}
    assert client.post("/api/v1/agents/events/batch", json=payload, headers=headers).status_code == 200
    with client.db_factory() as db:
        assert db.scalar(select(func.count()).select_from(Event)) == 1


def test_probe_target_management_and_numeric_bounds(client):
    _, identity = enroll(client)
    target = {"vps_id": identity["vps_id"], "address": "8.8.8.8", "port": 443}
    created = client.post("/api/v1/probe-targets", json=target)
    assert created.status_code == 200
    assert client.post("/api/v1/probe-targets", json=target).status_code == 409
    assert (
        client.patch("/api/v1/probe-targets/" + created.json()["id"], json={"enabled": False}).status_code
        == 200
    )
    assert client.get("/api/v1/probe-targets").json()["items"][0]["enabled"] is False
    invalid = batch()
    invalid["events"][0]["user_id"] = 2**64
    assert (
        client.post("/api/v1/agents/events/batch", json=invalid, headers=identity["headers"]).status_code
        == 422
    )


def test_batch_idempotency_search_and_conflict(client):
    _, identity = enroll(client)
    body = batch()
    for _ in range(2):
        response = client.post("/api/v1/agents/events/batch", json=body, headers=identity["headers"])
        assert response.status_code == 200, response.text
    with client.db_factory() as db:
        assert db.scalar(select(func.count()).select_from(Event)) == 1
    found = client.get("/api/v1/search?q=1.2.3.4").json()
    assert found["items"][0]["user_id"] == 12
    assert client.get("/api/v1/events?size=201").status_code == 422
    body["events"][0]["connections"] = 4
    assert (
        client.post("/api/v1/agents/events/batch", json=body, headers=identity["headers"]).status_code == 409
    )


def test_gzip_bomb_and_invalid_events(client):
    _, identity = enroll(client)
    response = client.post(
        "/api/v1/agents/events/batch",
        content=gzip.compress(b"a" * 5000000),
        headers=dict(identity["headers"], **{"Content-Encoding": "gzip"}),
    )
    assert response.status_code == 413
    for field, invalid in (
        ("source_ip", "999.1.1.1"),
        ("connections", -1),
        ("destination_port", 99999),
        ("bucket_start", (now() + timedelta(days=1)).isoformat()),
    ):
        body = batch()
        body["events"][0][field] = invalid
        assert (
            client.post("/api/v1/agents/events/batch", json=body, headers=identity["headers"]).status_code
            == 422
        )


def test_csrf_and_viewer_permissions(client):
    login(client)
    assert (
        client.post(
            "/api/v1/admin-users",
            json={"email": "viewer@example.test", "password": "viewer-password-123", "role": "viewer"},
        ).status_code
        == 200
    )
    assert (
        client.patch(
            "/api/v1/settings", json={"lookback_minutes": 30}, headers={"X-CSRF-Token": "bad"}
        ).status_code
        == 403
    )
    result = client.post(
        "/api/v1/auth/login", json={"email": "viewer@example.test", "password": "viewer-password-123"}
    ).json()
    client.headers["X-CSRF-Token"] = result["csrf_token"]
    assert client.get("/api/v1/events").status_code == 200
    assert client.post("/api/v1/enrollment-tokens", json={"kind": "agents"}).status_code == 403
    assert (
        client.get(
            "/api/v1/export",
            params={"start": (now() - timedelta(hours=1)).isoformat(), "end": now().isoformat()},
        ).status_code
        == 403
    )


def test_logout_revokes_session(client):
    login(client)
    assert client.post("/api/v1/auth/logout").status_code == 200
    assert client.get("/api/v1/events").status_code == 401
