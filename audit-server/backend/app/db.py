import os
import threading
import time
from datetime import datetime, timezone

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker


def now():
    return datetime.now(timezone.utc)


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    pass


database_url = os.environ.get("DATABASE_URL", "sqlite:///audit-development.db")
connection_options = (
    {"connect_timeout": 5, "options": "-c statement_timeout=30000 -c lock_timeout=5000"}
    if database_url.startswith("postgresql")
    else {}
)
engine = create_engine(database_url, pool_pre_ping=True, connect_args=connection_options)
Session = sessionmaker(engine, expire_on_commit=False)

query_metrics = {"count": 0, "seconds": 0.0}
query_lock = threading.Lock()


@event.listens_for(engine, "before_cursor_execute")
def query_start(conn, cursor, statement, parameters, context, executemany):
    context.audit_started = time.monotonic()


@event.listens_for(engine, "after_cursor_execute")
def query_end(conn, cursor, statement, parameters, context, executemany):
    with query_lock:
        query_metrics["count"] += 1
        query_metrics["seconds"] += time.monotonic() - context.audit_started


def session():
    with Session() as db:
        yield db
