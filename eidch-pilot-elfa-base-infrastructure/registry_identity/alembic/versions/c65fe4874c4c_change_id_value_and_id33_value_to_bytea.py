"""Change id_value and id33_value to bytea

Revision ID: c65fe4874c4c
Revises: bbe6af8b8d20
Create Date: 2025-01-31 14:38:36.180146

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c65fe4874c4c'
down_revision: Union[str, None] = 'bbe6af8b8d20'
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
