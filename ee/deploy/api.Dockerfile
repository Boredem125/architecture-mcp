# ee/deploy/api.Dockerfile -- Multi-stage build for the control-plane API.
#
# Build context: repository root (../../ from this file).
# Usage: docker build -f ee/deploy/api.Dockerfile .
#
# Image properties:
#   - Chainguard Python distroless final stage (no shell, no package manager)
#   - Non-root user (uid 65532, "nonroot")
#   - No build tools in the final stage
#   - Read-only root FS compatible (tmpfs for /tmp at runtime)
#   - Digest-pinned base images
#
# Base image:
#   Tag:    cgr.dev/chainguard/python:latest
#   Digest: sha256:e2ade4461c3ff67acf054214645e0b4e41b99140d7096ed64c1e15f6fe985cdf
#   Update policy: rebuild weekly; pin to latest digest after testing.
#   The free Chainguard tier publishes only :latest (no version pins).
#   Fallback: Wolfi via apko with explicit Python version, if the free
#   latest image changes Python major.minor and breaks ABI compatibility
#   with built wheels (see ee/deploy/README.md for details).

# ---------------------------------------------------------------------------
# Stage 1: build -- install Python packages (dev image has pip and shell)
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest-dev@sha256:6611f09b165b0ac0ff31c2ae2ac6fc7960483dfc568a7ee4f1bc4a59777287a8 AS build

# Run as root so pip installs to system site-packages (not --user).
USER root
WORKDIR /build

# Copy only dependency metadata first for layer caching
COPY pyproject.toml ./
COPY ee/pyproject.toml ./ee/

# Install the root (OSS connector) package
COPY src/ ./src/
RUN pip install --no-cache-dir --break-system-packages .

# Install the ee (control-plane) package
COPY ee/src/ ./ee/src/
RUN pip install --no-cache-dir --break-system-packages "./ee"

# Remove build-only packaging tools so they do not ship in the final stage
RUN pip uninstall -y pip setuptools wheel 2>/dev/null || true && \
    rm -rf /usr/lib/python3.15/site-packages/setuptools* \
           /usr/lib/python3.15/site-packages/pip* \
           /usr/lib/python3.15/site-packages/wheel* \
           /usr/lib/python3.15/site-packages/_distutils_hack* \
           /usr/lib/python3.15/site-packages/distutils_precedence.pth \
           /usr/lib/python3.15/site-packages/pkg_resources*

# ---------------------------------------------------------------------------
# Stage 2: runtime -- Chainguard distroless (no shell, no package manager)
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest@sha256:e2ade4461c3ff67acf054214645e0b4e41b99140d7096ed64c1e15f6fe985cdf

# Copy installed packages from the build stage
COPY --from=build /usr/lib/python3.15/site-packages/ /usr/lib/python3.15/site-packages/

# Copy Alembic migrations (they are inside the package, but ensure presence)
COPY ee/src/agg_cp/migrations/ /usr/lib/python3.15/site-packages/agg_cp/migrations/

USER 65532

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/usr/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"]

ENTRYPOINT ["python", "-m", "uvicorn", "agg_cp.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
