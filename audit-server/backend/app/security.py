import hashlib
import os
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select

from .db import now, session, utc
from .models import Admin, AuditLog, Identity, LoginSession

passwords = PasswordHasher()


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def audit(db, actor, action, **details):
    db.add(AuditLog(actor=actor, action=action, detail=details))


def current_user(request: Request, db=Depends(session)):
    token = request.cookies.get("audit_session", "")
    row = db.get(LoginSession, digest(token))
    if row is None or utc(row.expires_at) <= now():
        raise HTTPException(401, "authentication required")
    user = db.get(Admin, row.admin_id)
    if user is None or not user.enabled:
        raise HTTPException(401, "account disabled")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not secrets.compare_digest(row.csrf_hash, digest(request.headers.get("X-CSRF-Token", ""))):
            raise HTTPException(403, "CSRF validation failed")
    return user


def admin(user=Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(403, "admin required")
    return user


def agent(request: Request, db=Depends(session)):
    token = request.headers.get("Authorization", "")
    row = db.get(Identity, request.headers.get("X-Agent-ID", ""))
    if (
        row is None
        or not row.enabled
        or not token.startswith("Bearer ")
        or not secrets.compare_digest(row.token_hash, digest(token[7:]))
    ):
        raise HTTPException(401, "invalid agent credential")
    if row.kind not in request.url.path.split("/"):
        raise HTTPException(403, "credential scope mismatch")
    return row


def issue_session(db, user, response):
    token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    db.add(
        LoginSession(
            token_hash=digest(token),
            admin_id=user.id,
            csrf_hash=digest(csrf),
            expires_at=now() + timedelta(hours=8),
        )
    )
    secure = os.environ.get("APP_ENV", "production") != "test"
    response.set_cookie(
        "audit_session", token, secure=secure, httponly=True, samesite="strict", max_age=28800, path="/"
    )
    response.set_cookie(
        "audit_csrf", csrf, secure=secure, httponly=False, samesite="strict", max_age=28800, path="/"
    )
    return dict(csrf_token=csrf, role=user.role, email=user.email)


def bootstrap(db):
    if db.scalar(select(Admin.id).limit(1)):
        return
    email, password = os.environ.get("ADMIN_EMAIL"), os.environ.get("ADMIN_PASSWORD")
    if not email or not password or len(password) < 14:
        raise RuntimeError("first startup requires ADMIN_EMAIL and ADMIN_PASSWORD (14+ characters)")
    db.add(Admin(email=email.lower(), password_hash=passwords.hash(password), role="admin"))
    db.commit()
