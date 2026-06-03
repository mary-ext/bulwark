# syntax=docker/dockerfile:1

# ── Stage 1: build (toolchain via mise) ──────────────────────────────────────
# mise reads mise.toml and provides the exact rust/node/pnpm the project pins,
# so the image build matches local builds. See https://mise.jdx.dev/mise-cookbook/docker.html
FROM debian:trixie-slim AS build
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# build-essential: C toolchain for `ring` (rustls/quinn). git+curl+ca-certs for mise.
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
# Toolchain layer: only mise.toml invalidates the (slow) tool install.
COPY mise.toml ./
RUN mise trust && mise install

# Front-end bundle (embedded into the binary at compile time). The whole web/
# tree is copied so pnpm-workspace.yaml (allowBuilds) is present at install time.
COPY web/ web/
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    mise run install && mise run web

# Server binary. Cache the cargo registry + target dir across builds; the target
# cache isn't part of the image, so copy the binary out within the same layer.
COPY Cargo.toml Cargo.lock ./
# .cargo/config.toml carries the `--cfg reqwest_unstable` rustflag the HTTP/3
# upstream needs; without it reqwest's http3 feature refuses to compile.
COPY .cargo/ .cargo/
COPY crates/ crates/
COPY server/ server/
RUN --mount=type=cache,target=/cargo/registry \
    --mount=type=cache,target=/cargo/git \
    --mount=type=cache,target=/app/target \
    mise exec -- cargo build --release -p bulwark --bin bulwark \
    && cp target/release/bulwark /usr/local/bin/bulwark

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM debian:trixie-slim AS runtime
# ca-certificates: harmless extra trust roots (TLS upstreams bundle webpki-roots).
# curl: used by the HEALTHCHECK. libcap2-bin: grant the port-53 bind capability.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/bulwark /usr/local/bin/bulwark
# Let the unprivileged process bind 53 without running as root.
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/bulwark \
    && useradd --system --uid 10001 --home-dir /data --no-create-home bulwark \
    && mkdir -p /data && chown bulwark:bulwark /data

USER bulwark
ENV BULWARK_DATA_DIR=/data
# Config, filter lists, query log, and stats live here — mount a volume.
VOLUME ["/data"]

# DNS (UDP + TCP) and the web UI.
EXPOSE 53/udp 53/tcp 3000/tcp

# /api/status is public (no auth) and 200s once the HTTP server is up.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:3000/api/status || exit 1

ENTRYPOINT ["/usr/local/bin/bulwark"]
