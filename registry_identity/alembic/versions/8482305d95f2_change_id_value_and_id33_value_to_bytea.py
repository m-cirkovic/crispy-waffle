"""Change id_value and id33_value to bytea

Revision ID: 8482305d95f2
Revises: 1cf9fa5f84f9
Create Date: 2025-02-02 16:46:32.436943

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8482305d95f2'
down_revision: Union[str, None] = '1cf9fa5f84f9'
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
