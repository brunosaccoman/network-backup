"""Adiciona campos de validação de backup

Revision ID: 002_backup_validation
Revises: 001_performance_indexes
Create Date: 2025-11-20

Campos adicionados:
- validation_status: Status da validação (complete, incomplete, unknown)
- validation_message: Mensagem detalhada da validação
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '002_backup_validation'
down_revision = '001_performance_indexes'
branch_labels = None
depends_on = None


def upgrade():
    # Adicionar colunas de validação na tabela backups
    conn = op.get_bind()

    # Verificar se as colunas já existem (para evitar erro em execuções repetidas)
    conn.execute(sa.text('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'backups' AND column_name = 'validation_status'
            ) THEN
                ALTER TABLE backups ADD COLUMN validation_status VARCHAR(20) DEFAULT 'unknown';
            END IF;
        END $$;
    '''))

    conn.execute(sa.text('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'backups' AND column_name = 'validation_message'
            ) THEN
                ALTER TABLE backups ADD COLUMN validation_message TEXT;
            END IF;
        END $$;
    '''))

    # Criar índice para filtrar backups por status de validação
    conn.execute(sa.text('''
        CREATE INDEX IF NOT EXISTS idx_backup_validation_status ON backups(validation_status);
    '''))


def downgrade():
    op.drop_index('idx_backup_validation_status', table_name='backups')
    op.drop_column('backups', 'validation_message')
    op.drop_column('backups', 'validation_status')
