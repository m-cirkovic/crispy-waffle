"""Change id_value and id33_value to bytea

Revision ID: 8e2784d54a7f
Revises: 715415a45a09
Create Date: 2025-01-30 16:06:16.918141

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8e2784d54a7f'
down_revision: Union[str, None] = '715415a45a09'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###
