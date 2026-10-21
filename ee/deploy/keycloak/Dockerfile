# ee/deploy/keycloak/Dockerfile -- Pre-built Keycloak for the demo profile.
#
# Runs `kc.sh build` at image build time so that the runtime can use
# `start --optimized` with read_only: true.  Without this, `start-dev`
# performs a Quarkus augmentation at boot that writes to /opt/keycloak/lib,
# which fails on a read-only root filesystem.
#
# Demo-only: uses the H2 dev-file database (no external Postgres for KC).

FROM keycloak/keycloak:26.0.0@sha256:db0d0f2c2eee8618a37a50e04affb69823e56687b4d1b676a847a4b85de62178

# Build-time configuration: pre-compile with dev-file DB and health endpoint.
# Runtime options (KC_HTTP_ENABLED, KC_PROXY_HEADERS, etc.) are passed via
# environment variables at container start, not here.
RUN /opt/keycloak/bin/kc.sh build --db=dev-file --health-enabled=true

# The base image already runs as keycloak (uid 1000); name it so scanners
# and readers see the image does not end as root (Trivy DS-0002).
USER 1000
