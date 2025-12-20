# Multi-stage Dockerfile for Threat Hunting Playbook
# Stage 1: Builder - Install dependencies
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Runtime - CLI Tool
FROM python:3.11-slim as cli

LABEL maintainer="Threat Hunting Team"
LABEL description="AI-powered threat hunting playbook CLI tool"
LABEL version="2.0.0"

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application code
COPY src/ ./src/
COPY playbooks/ ./playbooks/
COPY setup.py .
COPY README.md .

# Make sure scripts are in PATH
ENV PATH=/root/.local/bin:$PATH

# Install the package
RUN pip install -e .

# Set default command
ENTRYPOINT ["hunt"]
CMD ["--help"]

# Stage 3: API Server
FROM python:3.11-slim as api

LABEL maintainer="Threat Hunting Team"
LABEL description="Threat Hunting Playbook REST API"
LABEL version="2.0.0"

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local

# Install additional API dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    redis \
    psycopg2-binary \
    sqlalchemy \
    pydantic-settings

# Copy application code
COPY src/ ./src/
COPY playbooks/ ./playbooks/
COPY api/ ./api/
COPY setup.py .

ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/app

# Install the package
RUN pip install -e .

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run API server
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
