# EnforceCore — Docker image for reproducible testing & benchmarks
# ----------------------------------------------------------------
# Build:  docker build -t enforcecore .
# Test:   docker run --rm enforcecore pytest
# Bench:  docker run --rm enforcecore python -m enforcecore.benchmarks.run
# Shell:  docker run --rm -it enforcecore bash

FROM python:3.12-slim AS base

LABEL maintainer="akios-ai" \
      org.opencontainers.image.source="https://github.com/akios-ai/EnforceCore" \
      org.opencontainers.image.description="EnforceCore — runtime enforcement for agentic AI"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system deps (none needed for now, but layer cached)
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Copy dependency metadata first for layer caching
COPY pyproject.toml README.md ./

# Install the package with all dev dependencies
COPY enforcecore/ enforcecore/
COPY tests/ tests/
COPY examples/ examples/

RUN pip install --no-cache-dir -e ".[dev]"

# Default: run the full test suite
CMD ["python", "-m", "pytest", "-v", "--tb=short"]
