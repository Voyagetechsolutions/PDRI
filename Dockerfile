# =============================================================================
# PDRI - Predictive Data Risk Infrastructure
# Multi-stage Dockerfile
# =============================================================================

# Stage 1: Builder
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Runtime
FROM python:3.12-slim AS runtime

LABEL maintainer="PDRI Team"
LABEL description="Predictive Data Risk Infrastructure API"
LABEL version="1.0.0"

# Create non-root user
RUN groupadd -r pdri && useradd -r -g pdri -d /app -s /sbin/nologin pdri

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY pdri/ ./pdri/
COPY shared/ ./shared/

# Set ownership
RUN chown -R pdri:pdri /app

# Switch to non-root user
USER pdri

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_LEVEL=INFO \
    API_HOST=0.0.0.0 \
    API_PORT=8000

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the API
CMD ["python", "-m", "uvicorn", "pdri.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
