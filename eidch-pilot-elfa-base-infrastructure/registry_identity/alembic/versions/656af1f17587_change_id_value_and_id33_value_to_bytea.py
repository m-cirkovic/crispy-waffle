"""Change id_value and id33_value to bytea

Revision ID: 656af1f17587
Revises: e0acb8661258
Create Date: 2025-02-05 09:03:07.778639

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '656af1f17587'
down_revision: Union[str, None] = 'e0acb8661258'
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
