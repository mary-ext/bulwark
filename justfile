# Bulwark task runner. Install `just`: https://github.com/casey/just
#
# The Rust build and the web build are decoupled: `cargo build` embeds whatever
# is already in `web/dist` and never runs pnpm. Build the front-end explicitly
# (via `just web`) before building a release binary, or use `just dist`.

# List available recipes.
default:
    @just --list

# Install front-end dependencies.
install:
    cd web && pnpm install

# Regenerate the OpenAPI spec the front-end API client is generated from.
spec:
    cargo run -p bulwark --bin gen-openapi > web/openapi.json

# Regenerate the typed API client (web/src/api/generated.ts) from the spec.
gen:
    cd web && pnpm gen

# Regenerate the spec and the client it feeds. Run after changing the API.
client: spec gen

# Build the front-end bundle into web/dist (embedded by the Rust build).
web:
    cd web && pnpm build

# Build the release binary, embedding the current web/dist.
build:
    cargo build --release

# Full release pipeline: spec -> client codegen -> UI bundle -> embedding binary.
dist: spec gen web build

# Run the server (debug). Override binds for local, unprivileged testing.
run:
    BULWARK_DNS_BIND=127.0.0.1:5353 BULWARK_HTTP_BIND=127.0.0.1:3000 cargo run

# Live UI dev: Vite dev server, proxying /api to a server on :3000.
# Run `just run` in another terminal.
dev:
    cd web && pnpm dev

# Checks.
test:
    cargo test --workspace

lint:
    cargo clippy --workspace --all-targets
    cd web && pnpm check

fmt:
    cargo fmt --all
