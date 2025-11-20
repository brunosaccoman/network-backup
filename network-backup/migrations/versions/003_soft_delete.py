"""Adiciona soft delete para devices e cache de dados em backups

Revision ID: 003_soft_delete
Revises: 002_backup_validation
Create Date: 2025-11-20

Campos adicionados em devices:
- deleted_at: Data/hora de exclusão (soft delete)
- deleted_by: ID do usuário que excluiu

Campos adicionados em backups:
- device_name_cached: Nome do device (para quando for excluído)
- device_ip_cached: IP do device (para quando for excluído)
- device_provedor_cached: Provedor do device (para quando for excluído)

Modificações:
- device_id em backups agora é nullable (para preservar backups de devices excluídos)
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '003_soft_delete'
down_revision = '002_backup_validation'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()

    # ==========================================================================
    # DEVICES - Adicionar campos de soft delete
    # ==========================================================================

    # deleted_at - Data/hora de exclusão
    conn.execute(sa.text('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'devices' AND column_name = 'deleted_at'
            ) THEN
                ALTER TABLE devices ADD COLUMN deleted_at TIMESTAMP;
            END IF;
        END $$;
    '''))

    # deleted_by - ID do usuário que excluiu
    conn.execute(sa.text('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'devices' AND column_name = 'deleted_by'
            ) THEN
                ALTER TABLE devices ADD COLUMN deleted_by INTEGER REFERENCES users(id);
            END IF;
        END $$;
    '''))

    # Índice para filtrar devices excluídos/ativos
    conn.execute(sa.text('''
        CREATE INDEX IF NOT EXISTS idx_device_deleted_at ON devices(deleted_at);
    '''))

    # ==========================================================================
    # BACKUPS - Adicionar campos de cache
    # ==========================================================================

    # device_name_cached - Nome do device no momento do backup
    conn.execute(sa.text('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'backups' AND column_name = 'device_name_cached'
            ) THEN
                ALTER TABLE backups ADD COLUMN device_name_cached VARCHAR(100);
            END IF;
        END $$;
    '''))

    # device_ip_cached - IP do device no momento do backup
    conn.execute(sa.text('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'backups' AND column_name = 'device_ip_cached'
            ) THEN
                ALTER TABLE backups ADD COLUMN device_ip_cached VARCHAR(45);
            END IF;
        END $$;
    '''))

    # device_provedor_cached - Provedor do device no momento do backup
    conn.execute(sa.text('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'backups' AND column_name = 'device_provedor_cached'
            ) THEN
                ALTER TABLE backups ADD COLUMN device_provedor_cached VARCHAR(100);
            END IF;
        END $$;
    '''))

    # ==========================================================================
    # BACKUPS - Tornar device_id nullable
    # ==========================================================================
    conn.execute(sa.text('''
        ALTER TABLE backups ALTER COLUMN device_id DROP NOT NULL;
    '''))

    # ==========================================================================
    # Preencher cache para backups existentes
    # ==========================================================================
    conn.execute(sa.text('''
        UPDATE backups b
        SET
            device_name_cached = d.name,
            device_ip_cached = d.ip_address,
            device_provedor_cached = d.provedor
        FROM devices d
        WHERE b.device_id = d.id
        AND b.device_name_cached IS NULL;
    '''))


def downgrade():
    # Remover índice
    op.drop_index('idx_device_deleted_at', table_name='devices')

    # Remover colunas de devices
    op.drop_column('devices', 'deleted_by')
    op.drop_column('devices', 'deleted_at')

    # Remover colunas de cache em backups
    op.drop_column('backups', 'device_provedor_cached')
    op.drop_column('backups', 'device_ip_cached')
    op.drop_column('backups', 'device_name_cached')
