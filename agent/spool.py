"""Transactional outbox and cursor; acknowledgements are the only normal delete path."""

import json
import logging
import random
import shutil
import sqlite3
import time
import uuid
from pathlib import Path


class Spool:
    def __init__(self, path, max_mb=512, retention_hours=72, reserve_mb=128):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.cap = int(max_mb * 1024 * 1024)
        self.retention = retention_hours * 3600
        self.reserve = reserve_mb * 1024 * 1024
        self.db = sqlite3.connect(str(path), timeout=0.1)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA wal_autocheckpoint=64;
            PRAGMA journal_size_limit=1048576;
            CREATE TABLE IF NOT EXISTS pending_batches (
                batch_id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
                created REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                next_try REAL NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS agent_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS dead_letter (
                batch_id TEXT PRIMARY KEY, reason TEXT NOT NULL, created REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS pending_due ON pending_batches(next_try, created);
            PRAGMA user_version=1;
        """)
        self.last_warning = 0
        # Bound the main database as well as logical payload. WAL needs its own
        # space; SQLite FULL rolls back the cursor instead of filling the host.
        self.db.execute(f"PRAGMA max_page_count={max(64, self.cap // 3 // 4096)}")

    def close(self):
        self.db.close()

    def state(self, key, default=None):
        row = self.db.execute("SELECT value FROM agent_state WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_state(self, key, value):
        self.db.execute(
            "INSERT INTO agent_state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value, separators=(",", ":"))),
        )

    def size(self):
        return sum(p.stat().st_size for p in self.path.parent.glob(self.path.name + "*") if p.is_file())

    def commit(self, kind, rows, cursor=None, max_events=1000, max_bytes=1048576, marker=None):
        """All batches and the log cursor advance atomically, including an empty read."""
        max_bytes = min(max_bytes, self.cap // 4)
        batches, current, size = [], [], 256
        for row in rows:
            row_size = len(json.dumps(row, ensure_ascii=True).encode()) + 2
            if row_size + 256 > max_bytes:
                raise ValueError("single event exceeds batch limit")
            if current and (len(current) >= max_events or size + row_size > max_bytes):
                batches.append(current)
                current, size = [], 256
            current.append(row)
            size += row_size
        if current:
            batches.append(current)
        if shutil.disk_usage(self.path.parent).free < self.reserve:
            raise OSError("audit disk reserve reached")
        now = time.time()
        with self.db:
            self.db.execute("DELETE FROM pending_batches WHERE created < ?", (now - self.retention,))
            sequence = self.state("sequence", 0)
            used = self.db.execute("SELECT coalesce(sum(length(payload)),0) FROM pending_batches").fetchone()[
                0
            ]
            dropped = 0
            for items in batches:
                sequence += 1
                batch_id = f"{int(now * 1000):013d}-{uuid.uuid4().hex}"
                body = json.dumps(
                    dict(
                        batch_id=batch_id, sequence=sequence, schema_version=2, created_at=now, events=items
                    ),
                    separators=(",", ":"),
                )
                # Evict before inserting, so even a large read cannot transiently
                # grow the database beyond its configured forensic budget.
                while used + len(body) > self.cap // 4:
                    oldest = self.db.execute(
                        "SELECT batch_id,length(payload) FROM pending_batches ORDER BY created,batch_id LIMIT 1"
                    ).fetchone()
                    if oldest is None:
                        raise ValueError("batch exceeds spool payload capacity")
                    self.db.execute("DELETE FROM pending_batches WHERE batch_id=?", (oldest[0],))
                    used -= oldest[1]
                    dropped += 1
                self.db.execute(
                    "INSERT INTO pending_batches(batch_id,kind,payload,created) VALUES (?,?,?,?)",
                    (batch_id, kind, body, now),
                )
                used += len(body)
            self.set_state("sequence", sequence)
            if cursor is not None:
                self.set_state("cursor", cursor)
            if marker is not None:
                self.set_state(marker, True)
            # Reserve space for SQLite pages and WAL. Evictions are explicitly counted.
            used = self.db.execute("SELECT coalesce(sum(length(payload)),0) FROM pending_batches").fetchone()[
                0
            ]
            while used > self.cap // 3:
                row = self.db.execute(
                    "SELECT batch_id,length(payload) FROM pending_batches ORDER BY created,batch_id LIMIT 1"
                ).fetchone()
                if row is None:
                    break
                self.db.execute("DELETE FROM pending_batches WHERE batch_id=?", (row[0],))
                used -= row[1]
                dropped += 1
            if dropped:
                self.set_state("evicted_batches", self.state("evicted_batches", 0) + dropped)
                if now - self.last_warning > 300:
                    logging.warning("audit spool capacity reached; oldest forensic batches evicted")
                    self.last_warning = now
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        if self.size() > self.cap:
            self.db.execute("VACUUM")

    def due(self):
        return self.db.execute(
            "SELECT * FROM pending_batches WHERE next_try<=? ORDER BY created,batch_id LIMIT 1",
            (time.time(),),
        ).fetchone()

    def ack(self, batch_id):
        with self.db:
            self.db.execute("DELETE FROM pending_batches WHERE batch_id=?", (batch_id,))
            self.set_state("last_upload", time.time())

    def retry(self, batch_id, permanent=False, status=0):
        with self.db:
            row = self.db.execute(
                "SELECT attempts FROM pending_batches WHERE batch_id=?", (batch_id,)
            ).fetchone()
            if row is None:
                return
            attempts = row[0] + 1
            delay = min(3600, 2 ** min(attempts, 11)) * random.uniform(0.75, 1.25)
            self.db.execute(
                "UPDATE pending_batches SET attempts=?,next_try=? WHERE batch_id=?",
                (attempts, time.time() + delay, batch_id),
            )
            if permanent:
                self.db.execute(
                    "INSERT OR REPLACE INTO dead_letter VALUES (?,?,?)", (batch_id, str(status), time.time())
                )
                self.db.execute(
                    "DELETE FROM dead_letter WHERE batch_id NOT IN (SELECT batch_id FROM dead_letter ORDER BY created DESC LIMIT 100)"
                )

    def health(self):
        row = self.db.execute("SELECT count(*),min(created) FROM pending_batches").fetchone()
        return dict(
            spool_rows=row[0],
            spool_bytes=self.size(),
            spool_capacity=self.cap,
            oldest_batch=row[1],
            last_upload=self.state("last_upload"),
            evicted_batches=self.state("evicted_batches", 0),
            spool_usage_ratio=min(
                1.0,
                self.db.execute("SELECT coalesce(sum(length(payload)),0) FROM pending_batches").fetchone()[0]
                / (self.cap // 4),
            ),
        )
