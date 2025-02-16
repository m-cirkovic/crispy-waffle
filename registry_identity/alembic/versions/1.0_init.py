from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '1.0'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.execute('CREATE SCHEMA IF NOT EXISTS public')
    op.create_table(
        "identity",
        sa.Column("index", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("id_value", sa.BigInteger, nullable=False),
        sa.Column("id33_value", sa.BigInteger, nullable=False),
        sa.Column("active", sa.Boolean, nullable=False, default=True),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False),
        schema='public'
    )
        

def downgrade() -> None:
    op.drop_table("identity")