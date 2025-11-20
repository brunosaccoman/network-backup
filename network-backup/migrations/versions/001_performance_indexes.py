"""Adiciona índices de performance para escalabilidade

Revision ID: 001_performance_indexes
Revises: e86281ee7893
Create Date: 2025-11-20

Índices otimizados para:
- Listagem de devices com contagem de backups
- Dashboard com estatísticas agregadas
- Filtros por provedor e status
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '001_performance_indexes'
down_revision = 'e86281ee7893'
branch_labels = None
depends_on = None


def upgrade():
    # Usar execute para criar índices com IF NOT EXISTS (PostgreSQL)
    # Isso evita erros se os índices já existirem

    conn = op.get_bind()

    # Índices para tabela backups
    conn.execute(sa.text('''
        CREATE INDEX IF NOT EXISTS idx_backup_device_id ON backups(device_id);
    '''))

    conn.execute(sa.text('''
        CREATE INDEX IF NOT EXISTS idx_backup_status ON backups(status);
    '''))

    conn.execute(sa.text('''
        CREATE INDEX IF NOT EXISTS idx_backup_date_desc ON backups(backup_date DESC);
    '''))

    # Índice composto para queries de estatísticas (dashboard)
    conn.execute(sa.text('''
        CREATE INDEX IF NOT EXISTS idx_backup_date_status ON backups(backup_date, status);
    '''))

    # Índices para tabela devices
    conn.execute(sa.text('''
        CREATE INDEX IF NOT EXISTS idx_device_active ON devices(active);
    '''))

    conn.execute(sa.text('''
        CREATE INDEX IF NOT EXISTS idx_device_provedor_active ON devices(provedor, active);
    '''))

    # Índice para ordenação por nome (listagem)
    conn.execute(sa.text('''
        CREATE INDEX IF NOT EXISTS idx_device_name_lower ON devices(lower(name));
    '''))


def downgrade():
    op.drop_index('idx_backup_device_id', table_name='backups')
    op.drop_index('idx_backup_status', table_name='backups')
    op.drop_index('idx_backup_date_desc', table_name='backups')
    op.drop_index('idx_backup_date_status', table_name='backups')
    op.drop_index('idx_device_active', table_name='devices')
    op.drop_index('idx_device_provedor_active', table_name='devices')
    op.drop_index('idx_device_name_lower', table_name='devices')
