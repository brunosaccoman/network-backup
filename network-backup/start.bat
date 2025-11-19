@echo off
echo ========================================
echo   Network Backup System - Inicializacao
echo ========================================
echo.

echo [1/5] Verificando Docker Desktop...
docker version >nul 2>&1
if errorlevel 1 (
    echo [ERRO] Docker Desktop nao esta rodando!
    echo.
    echo Por favor:
    echo 1. Abra o Docker Desktop
    echo 2. Aguarde ate ele iniciar completamente
    echo 3. Execute este script novamente
    echo.
    pause
    exit /b 1
)
echo [OK] Docker Desktop esta rodando

echo.
echo [2/5] Parando containers antigos (se existirem)...
docker-compose down 2>nul
echo [OK] Containers parados

echo.
echo [3/5] Construindo e iniciando containers...
docker-compose up -d --build
if errorlevel 1 (
    echo [ERRO] Falha ao iniciar containers!
    pause
    exit /b 1
)
echo [OK] Containers iniciados

echo.
echo [4/5] Aguardando PostgreSQL ficar pronto...
timeout /t 10 /nobreak >nul
echo [OK] PostgreSQL deve estar pronto

echo.
echo [5/5] Verificando status dos containers...
docker-compose ps

echo.
echo ========================================
echo   Sistema iniciado com sucesso!
echo ========================================
echo.
echo Acesse: http://localhost:8000
echo.
echo Logs da aplicacao:
echo   docker-compose logs -f app
echo.
echo Para parar:
echo   docker-compose down
echo.
pause
