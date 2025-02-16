from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision = '1.1'
down_revision = '1.0'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Create service table
    op.create_table(
        "service",
        sa.Column("index", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String, nullable=False, unique=True)
    )
    
    # Insert default services
    op.execute(
        """
        INSERT INTO service (name) VALUES 
        ('Service1'), ('Service2'), ('Service3')
        """
    )

def downgrade() -> None:
    op.drop_table("service")