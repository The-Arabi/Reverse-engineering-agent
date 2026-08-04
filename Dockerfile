# Dockerfile for Reverse Engineering Lab
# Multi-stage build with Ghidra, GDB, QEMU, radare2, and RE tools

# ===========================================================================
# Stage 1: Builder — install Python deps
# ===========================================================================
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ===========================================================================
# Stage 2: Runtime — RE tools + application
# ===========================================================================
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV REVERSE_ENGINEERING_ENV=production
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# System deps + RE tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core build tools
    gcc g++ make git curl wget unzip ca-certificates gnupg \
    # Binary analysis tools
    binutils file \
    # Network analysis
    tshark tcpdump \
    # Debugging
    gdb strace ltrace \
    # Emulation
    qemu-user-static qemu-system-x86 \
    # radare2 (from GitHub releases)
    && ARCH=$(dpkg --print-architecture) \
    && curl -fsSL "https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_${ARCH}.deb" -o /tmp/r2.deb \
    && dpkg -i /tmp/r2.deb || apt-get install -f -y \
    && rm -f /tmp/r2.deb \
    # Python build deps (for psycopg2 etc.)
    && apt-get install -y --no-install-recommends libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra (headless) — lightweight install
ARG GHIDRA_VERSION=11.1.2
RUN curl -fsSL "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20240709.zip" -o /tmp/ghidra.zip \
    && apt-get update && apt-get install -y --no-install-recommends default-jdk-headless \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && ln -s /opt/ghidra_*/support/analyzeHeadless /usr/local/bin/analyzeHeadless \
    && rm -f /tmp/ghidra.zip \
    && rm -rf /var/lib/apt/lists/*

# Copy Python deps from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data logs config modules monitoring/prometheus monitoring/grafana

# Non-root user
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app
USER appuser

# Expose ports:
#   5000  — Web dashboard
#   8001  — Ghidra MCP server
#   8002  — Debugger MCP server
#   9090  — Prometheus metrics
#   3000  — Grafana (external, not in this container)
EXPOSE 5000 8001 8002 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Default command
CMD ["python", "startup.py"]
