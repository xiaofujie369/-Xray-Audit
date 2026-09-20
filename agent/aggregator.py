"""Bounded in-memory aggregation; caller commits before advancing its cursor."""

from datetime import datetime, timezone


class Aggregator:
    def __init__(self, seconds=60, max_keys=50000):
        if not 1 <= seconds <= 3600 or max_keys < 1:
            raise ValueError("invalid aggregation limits")
        self.seconds, self.max_keys = seconds, max_keys
        self.buckets = {}

    def add(self, event):
        event = dict(event)
        stamp = event.pop("event_time")
        epoch = datetime.fromisoformat(stamp).timestamp()
        bucket = datetime.fromtimestamp(epoch // self.seconds * self.seconds, timezone.utc).isoformat()
        key = (bucket, tuple(sorted(event.items())))
        if key not in self.buckets:
            if len(self.buckets) >= self.max_keys:
                raise BufferError("flush required")
            self.buckets[key] = dict(
                event,
                bucket_start=bucket,
                bucket_seconds=self.seconds,
                connections=0,
                first_seen=stamp,
                last_seen=stamp,
            )
        row = self.buckets[key]
        row["connections"] += 1
        row["first_seen"] = min(row["first_seen"], stamp)
        row["last_seen"] = max(row["last_seen"], stamp)

    def rows(self):
        return list(self.buckets.values())
