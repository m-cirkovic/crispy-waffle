"""Change id_value and id33_value to bytea

Revision ID: eedd4e825ad0
Revises: 07f87984421b
Create Date: 2025-01-30 13:21:38.211321

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'eedd4e825ad0'
down_revision: Union[str, None] = '07f87984421b'
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
