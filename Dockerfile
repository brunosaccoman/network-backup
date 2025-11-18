# Multi-stage build para reduzir tamanho da imagem
FROM python:3.11-slim as builder

# Instalar dependências de build
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Criar ambiente virtual
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copiar requirements e instalar
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ============================================================================
# Imagem final
# ============================================================================
FROM python:3.11-slim

# Instalar apenas dependências de runtime
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copiar ambiente virtual do builder
COPY --from=builder /opt/venv /opt/venv

# Criar usuário não-root (ou usar existente)
RUN id -u backup &>/dev/null || useradd -m -u 1000 backup && \
    mkdir -p /app /app/backups /app/logs && \
    chown -R backup:backup /app

# Definir diretório de trabalho
WORKDIR /app

# Copiar código da aplicação
COPY --chown=backup:backup . .

# Usar ambiente virtual
ENV PATH="/opt/venv/bin:$PATH"

# Mudar para usuário não-root
USER backup

# Expor porta
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Comando para iniciar aplicação
CMD ["gunicorn", "-c", "gunicorn_config.py", "app:app"]
