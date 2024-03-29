"""Initial migration

Revision ID: 7b52153e974e
Revises: a2141e988c04
Create Date: 2023-03-04 20:42:37.337317

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "7b52153e974e"
down_revision = "a2141e988c04"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table("login_history", schema=None) as batch_op:
        batch_op.create_unique_constraint(None, ["id"])

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.create_unique_constraint(None, ["id"])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_constraint(None, type_="unique")

    with op.batch_alter_table("login_history", schema=None) as batch_op:
        batch_op.drop_constraint(None, type_="unique")

    # ### end Alembic commands ###
