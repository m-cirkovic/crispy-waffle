"""Change id_value and id33_value to bytea

Revision ID: 47c6a73ea6f5
Revises: 3584627daf9a
Create Date: 2025-02-19 10:51:51.944130

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '47c6a73ea6f5'
down_revision: Union[str, None] = '3584627daf9a'
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
