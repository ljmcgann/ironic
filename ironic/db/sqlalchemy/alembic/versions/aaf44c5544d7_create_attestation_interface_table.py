# Copyright 2016 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""create_attestation_interface_table

Revision ID: aaf44c5544d7
Revises: c1846a214450
Create Date: 2021-07-19 16:56:19.199934

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'aaf44c5544d7'
down_revision = 'c1846a214450'


def upgrade():
    op.add_column('nodes', sa.Column('attestation_interface', sa.String(255),
                                     nullable=True))
