# ee/deploy/api.Dockerfile -- Multi-stage build for the control-plane API.
#
# Build context: repository root (../../ from this file).
# Usage: docker build -f ee/deploy/api.Dockerfile .
#
# Image properties:
#   - Non-root user (uid 10001)
#   - No build tools in the final stage
#   - Read-only root FS compatible (tmpfs for /tmp at runtime)
#   - HEALTHCHECK on /health

# ---------------------------------------------------------------------------
# Stage 1: build -- install Python packages
# ---------------------------------------------------------------------------
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS build
# python:3.12-slim

WORKDIR /build

# Install build-time system dependencies (needed for psycopg binary wheels)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy only dependency metadata first for layer caching
COPY pyproject.toml ./
COPY ee/pyproject.toml ./ee/

# Install the root (OSS connector) package
COPY src/ ./src/
RUN pip install --no-cache-dir .

# Install the ee (control-plane) package
COPY ee/src/ ./ee/src/
RUN pip install --no-cache-dir "./ee"

# Remove build-only packaging tools so they do not ship in the final stage
RUN pip uninstall -y pip setuptools wheel 2>/dev/null || true

# ---------------------------------------------------------------------------
# Stage 2: runtime -- lean final image
# ---------------------------------------------------------------------------
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS runtime
# python:3.12-slim

# Install only the runtime C library for psycopg (no compiler)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 && \
    rm -rf /var/lib/apt/lists/*

# Copy installed packages from the build stage
COPY --from=build /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=build /usr/local/bin/ /usr/local/bin/

# Copy Alembic migrations (they are inside the package, but ensure presence)
COPY ee/src/agg_cp/migrations/ /usr/local/lib/python3.12/site-packages/agg_cp/migrations/

# Create a non-root user
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin appuser

USER 10001

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

ENTRYPOINT ["uvicorn", "agg_cp.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
