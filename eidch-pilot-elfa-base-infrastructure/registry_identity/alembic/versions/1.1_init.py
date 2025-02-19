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
        ('c8d9dfa6f2439bcb0fdf00efaf4a4577d141a85902b0b75b01d2992fad5912c3'),
        ('6363ec6388af474c4352d04a25fd650ca8e913eb89bb890444f503f0c7f85151'),
        ('0c2b2edd588fe2f2d08eedc0437433d88615e0212c3dee3109f67aae98c66c04')
        """
    )

def downgrade() -> None:
    op.drop_table("service")