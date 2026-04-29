FROM python:3.11-slim

WORKDIR /app

# Install iptables and iproute2 (required for IP blocking)
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files and install first (layer cache)
COPY requirements.txt ./
RUN uv pip install --system -r requirements.txt

# Copy application code into /app/detector/ so it is importable as a package.
# The build context is ./detector, so "COPY . ./detector/" places all module
# files under /app/detector/__init__.py, /app/detector/main.py, etc.
# Running "python -m detector" from /app then finds the package correctly.
COPY . ./detector/

# Create audit log directory
RUN mkdir -p /var/log/anomaly-detector

# Run as root — required for iptables calls
CMD ["python", "-m", "detector"]
