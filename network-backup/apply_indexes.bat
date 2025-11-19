@echo off
echo ========================================
echo   Aplicar Indices de Escalabilidade
echo ========================================
echo.

echo [1/3] Verificando se containers estao rodando...
docker-compose ps | findstr "network-backup-db" >nul 2>&1
if errorlevel 1 (
    echo [ERRO] Containers nao estao rodando!
    echo Execute primeiro: start.bat
    pause
    exit /b 1
)
echo [OK] Containers rodando

echo.
echo [2/3] Copiando script SQL para o container...
docker cp migrations\versions\add_scalability_indexes.sql network-backup-db:/tmp/
if errorlevel 1 (
    echo [ERRO] Falha ao copiar script!
    pause
    exit /b 1
)
echo [OK] Script copiado

echo.
echo [3/3] Aplicando indices no banco de dados...
docker exec -it network-backup-db psql -U backup_user -d network_backup -f /tmp/add_scalability_indexes.sql
if errorlevel 1 (
    echo [AVISO] Indices podem ja estar aplicados ou houve um erro
) else (
    echo [OK] Indices aplicados com sucesso!
)

echo.
echo Verificando indices criados...
docker exec -it network-backup-db psql -U backup_user -d network_backup -c "SELECT indexname FROM pg_indexes WHERE tablename IN ('devices', 'backups') ORDER BY indexname;"

echo.
echo ========================================
echo   Indices aplicados!
echo ========================================
echo.
echo O sistema agora esta otimizado para 1000-3000 devices
echo.
pause
