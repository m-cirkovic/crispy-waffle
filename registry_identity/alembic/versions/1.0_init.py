from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '1.0'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    inspector = sa.Inspector.from_engine(op.get_bind())
    existing_tables = inspector.get_table_names()
    
    if "identity" not in existing_tables:
        op.create_table(
            "identity",
            sa.Column("index", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column("id_value", sa.BigInteger, nullable=False),
            sa.Column("id33_value", sa.BigInteger, nullable=False),
            sa.Column("active", sa.Boolean, nullable=False, default=True),
            sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False)
        )
        
        # Add indexes for efficient lookups
        op.create_index(
            'ix_identity_id_values',
            'identity',
            ['id_value', 'id33_value']
        )

def downgrade() -> None:
    op.drop_table("identity")