FROM python:3.11-slim AS base

WORKDIR /app

# Install iptables and other system deps
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files
COPY pyproject.toml requirements.txt ./

# Install dependencies
RUN uv pip install --system -r requirements.txt

# Copy application code
COPY . .

# Create log directory
RUN mkdir -p /var/log/anomaly-detector

# Run as root (required for iptables)
CMD ["python", "-m", "detector"]
