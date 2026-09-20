"""Durable aggregate operational counters."""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "operational_counters",
        sa.Column("name", sa.String(80), primary_key=True),
        sa.Column("value", sa.BigInteger(), nullable=False),
    )


def downgrade():
    op.drop_table("operational_counters")
