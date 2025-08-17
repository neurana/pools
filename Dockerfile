# Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependências de sistema úteis para compilar libs dos skills (uvloop, cryptography, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc libffi-dev libssl-dev git curl tini \
 && rm -rf /var/lib/apt/lists/*

# Instala dependências do agente
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Código
COPY agent ./agent
COPY config ./config
COPY job_runner.py ./job_runner.py

# Diretório de dados persistentes
RUN useradd -ms /bin/bash appuser && mkdir -p /data && chown -R appuser:appuser /app /data
USER appuser

# Envs úteis em Docker
ENV AGENT_CONFIG=/app/config/agent.toml \
    AGENT_BASE_DIR=/data \
    AGENT_SECRETS_DIR=/data/_secrets \
    AGENT_BIND_HOST=0.0.0.0

EXPOSE 8081 18000-19999

ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["python","-m","agent.app"]
