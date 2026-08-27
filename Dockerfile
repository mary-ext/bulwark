# syntax=docker/dockerfile:1

# Build
FROM debian:trixie-slim AS build
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Native dependencies and mise prerequisites.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl git ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/*

ENV MISE_DATA_DIR=/mise \
    MISE_CONFIG_DIR=/mise \
    MISE_CACHE_DIR=/mise/cache \
    MISE_INSTALL_PATH=/usr/local/bin/mise \
    CARGO_HOME=/cargo \
    PATH=/mise/shims:/cargo/bin:$PATH
RUN curl https://mise.run | sh

WORKDIR /app
# Cache toolchain installation.
COPY mise.toml ./
RUN mise trust && mise install

# Build the embedded frontend.
COPY web/ web/
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    mise run install && mise run web

# Build the server with Cargo caches.
COPY Cargo.toml Cargo.lock ./
COPY .cargo/ .cargo/
COPY crates/ crates/
COPY server/ server/
RUN --mount=type=cache,target=/cargo/registry \
    --mount=type=cache,target=/cargo/git \
    --mount=type=cache,target=/app/target \
    mise exec -- cargo build --release -p bulwark --bin bulwark \
    && cp target/release/bulwark /usr/local/bin/bulwark

# Runtime
FROM debian:trixie-slim AS runtime
# Certificates, health checks, capabilities, and privilege drop.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libcap2-bin gosu \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/bulwark /usr/local/bin/bulwark
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Allow the service user to bind port 53.
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/bulwark \
    && useradd --system --uid 10001 --home-dir /data --no-create-home bulwark \
    && mkdir -p /data && chown bulwark:bulwark /data \
    && chmod +x /usr/local/bin/docker-entrypoint.sh

# The entrypoint fixes `/data` ownership before dropping privileges.
ENV BULWARK_DATA_DIR=/data
# Persistent application data.
VOLUME ["/data"]

# DNS and web UI.
EXPOSE 53/udp 53/tcp 3000/tcp

# Public readiness endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:3000/api/status || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
