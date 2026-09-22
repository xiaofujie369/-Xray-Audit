"""Explicit upgrade option: ordinary detail 7 days, saved evidence/baseline 90 days."""

from .db import Session
from .models import Setting


def main():
    with Session() as db:
        for key, value in {"event_retention_days": 7, "traffic_retention_days": 7,
                           "incident_retention_days": 90, "correlation_retention_days": 90,
                           "baseline_retention_days": 90}.items():
            db.merge(Setting(key=key, value=value))
        db.commit()
    print("Retention: ordinary detail 7 days; closed incident evidence and baselines 90 days. Open incidents retained.")


if __name__ == "__main__":
    main()
