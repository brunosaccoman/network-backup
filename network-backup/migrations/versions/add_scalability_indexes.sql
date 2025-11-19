-- Migration: Adicionar índices de escalabilidade para 1000+ devices
-- Data: 2025-11-19
-- Descrição: Adiciona índices compostos para otimizar queries em ambientes com milhares de dispositivos

-- Índices para tabela devices
CREATE INDEX IF NOT EXISTS idx_device_active_updated ON devices (active, updated_at);
CREATE INDEX IF NOT EXISTS idx_device_provedor ON devices (provedor);

-- Índices para tabela backups
CREATE INDEX IF NOT EXISTS idx_backup_device_date ON backups (device_id, backup_date);
CREATE INDEX IF NOT EXISTS idx_backup_status_date ON backups (status, backup_date);

-- Comentários para documentação
COMMENT ON INDEX idx_device_active_updated IS 'Otimiza queries de devices ativos ordenados por data de atualização';
COMMENT ON INDEX idx_device_provedor IS 'Otimiza filtros por provedor';
COMMENT ON INDEX idx_backup_device_date IS 'Otimiza queries de backups por device e data';
COMMENT ON INDEX idx_backup_status_date IS 'Otimiza queries de backups por status (failed/success) e data';
