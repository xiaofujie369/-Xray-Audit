import os

from .models import Setting

DEFAULTS = {
    "lookback_minutes": 60,
    "fail_consecutive": 2,
    "recover_consecutive": 2,
    "min_distinct_probes": 2,
    "probe_interval_seconds": 300,
    "event_retention_days": 30,
    "traffic_retention_days": 90,
    "incident_retention_days": 365,
    "correlation_retention_days": 365,
    "admin_log_retention_days": 365,
    "domain_ignore": [],
    "timezone": "browser",
    "control_targets": [],
    "weights": [0.30, 0.25, 0.20, 0.15, 0.10],
}
ENV_KEYS = {
    "lookback_minutes": "BLOCK_EVENT_LOOKBACK_MINUTES",
    "fail_consecutive": "BLOCK_FAIL_CONSECUTIVE",
    "recover_consecutive": "BLOCK_RECOVER_CONSECUTIVE",
    "min_distinct_probes": "BLOCK_MIN_DISTINCT_PROBES",
    "event_retention_days": "AUDIT_RAW_RETENTION_DAYS",
    "traffic_retention_days": "AUDIT_TRAFFIC_RETENTION_DAYS",
    "incident_retention_days": "AUDIT_BLOCK_EVENT_RETENTION_DAYS",
    "correlation_retention_days": "AUDIT_CORRELATION_RETENTION_DAYS",
    "admin_log_retention_days": "AUDIT_ADMIN_LOG_RETENTION_DAYS",
}


def settings(db):
    values = dict(DEFAULTS)
    if os.environ.get("AUDIT_DOMAIN_IGNORE"):
        values["domain_ignore"] = [
            x.strip().lower().rstrip(".") for x in os.environ["AUDIT_DOMAIN_IGNORE"].split(",") if x.strip()
        ]
    for key, env in ENV_KEYS.items():
        if env in os.environ:
            values[key] = int(os.environ[env])
    for key in values:
        row = db.get(Setting, key)
        if row is not None:
            values[key] = row.value
    return values
