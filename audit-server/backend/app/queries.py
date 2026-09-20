from sqlalchemy import String, cast, func, select

from .models import Event


def activity_summary(db, filters):
    totals = db.execute(
        select(
            func.coalesce(func.sum(Event.connections), 0),
            func.min(Event.first_seen),
            func.max(Event.last_seen),
            func.count(func.distinct(Event.vps_id)),
            func.count(func.distinct(Event.user_id)),
            func.count(func.distinct(Event.source_ip)),
        ).where(*filters)
    ).one()
    result = dict(
        connections=totals[0],
        first_seen=totals[1],
        last_seen=totals[2],
        distinct_vps=totals[3],
        distinct_users=totals[4],
        distinct_source_ips=totals[5],
    )
    hour = func.substr(cast(Event.bucket_start, String), 1, 13)
    result["connection_trend"] = [
        {"label": stamp + ":00 UTC", "value": count}
        for stamp, count in db.execute(
            select(hour, func.sum(Event.connections)).where(*filters).group_by(hour).order_by(hour).limit(744)
        )
    ]
    for field in (
        Event.vps_id,
        Event.node_id,
        Event.user_id,
        Event.source_ip,
        Event.destination_domain,
        Event.destination_ip,
    ):
        rows = db.execute(
            select(field, func.sum(Event.connections).label("connections"))
            .where(*filters, field.is_not(None))
            .group_by(field)
            .order_by(func.sum(Event.connections).desc())
            .limit(20)
        )
        result[field.key] = [{"entity": key, "connections": connections} for key, connections in rows]
    return result
