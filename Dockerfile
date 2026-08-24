FROM python:3.11-slim

WORKDIR /app

# Install build deps for psycopg2-binary
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# #231: never run as root. This image carries only the agent/runtime role
# (Glama introspection start-up); the trust-owner uid separation that makes
# strict mode a real boundary is a host-deployment concern, documented in
# docs/deploy/dedicated-uid-deployment.md. A dedicated non-login system user
# with its own writable HOME is the minimum this image can enforce on its own
# — WILLOW_HOME defaults to $HOME/.willow (see src/willow_mcp/paths.py), so the
# user needs a home it owns.
RUN useradd --system --create-home --home-dir /home/willow \
        --shell /usr/sbin/nologin willow \
    && mkdir -p /home/willow/.willow \
    && chown -R willow:willow /home/willow /app
ENV HOME=/home/willow

USER willow

# Glama only needs the server to start and respond to introspection.
# SAP auth is disabled when no PGP fingerprint is set.
# Postgres is optional — server degrades gracefully without it.
ARG WILLOW_APP_ID=glama-inspect
ENV WILLOW_APP_ID=${WILLOW_APP_ID}

CMD ["python", "-m", "willow_mcp"]
