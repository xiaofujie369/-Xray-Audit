"""Versioned incident evidence survives raw-event retention."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("probe_results", sa.Column("control_revision", sa.String(64)))
    op.add_column("block_events", sa.Column("investigation_dirty", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.create_table(
        "investigation_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("block_event_id", sa.String(36), sa.ForeignKey("block_events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("block_event_id", "content_hash"),
    )
    op.create_index("ix_investigation_snapshots_block_event_id", "investigation_snapshots", ["block_event_id"])
    op.create_table(
        "hourly_baselines",
        sa.Column("vps_id", sa.String(36), sa.ForeignKey("vps.id"), primary_key=True),
        sa.Column("hour_start", sa.DateTime(timezone=True), primary_key=True),
        sa.Column("entity_type", sa.String(20), primary_key=True),
        sa.Column("entity_hash", sa.String(64), primary_key=True),
        sa.Column("connections", sa.BigInteger(), nullable=False),
    )
    op.create_index("ix_hourly_baselines_hour_start", "hourly_baselines", ["hour_start"])
    op.create_table(
        "ai_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("snapshot_id", sa.String(36), sa.ForeignKey("investigation_snapshots.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("result", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_token", sa.String(36)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_ai_reports_status", "ai_reports", ["status"])
    op.create_index("ix_ai_reports_available_at", "ai_reports", ["available_at"])
    settings = sa.table("settings", sa.column("key", sa.String), sa.column("value", sa.JSON))
    boundary = op.get_bind().execute(sa.text("SELECT COALESCE(MAX(id), 0) FROM audit_events_1m")).scalar()
    op.bulk_insert(settings, [
        {"key": "baseline_backfill", "value": {"cursor": 0, "max_id": int(boundary)}},
        {"key": "ai_daily_usage", "value": {"day": "", "requests": 0}},
    ])


def downgrade():
    op.execute("DELETE FROM settings WHERE key IN ('baseline_backfill', 'ai_daily_usage')")
    op.drop_table("ai_reports")
    op.drop_table("hourly_baselines")
    op.drop_table("investigation_snapshots")
    op.drop_column("block_events", "investigation_dirty")
    op.drop_column("probe_results", "control_revision")
