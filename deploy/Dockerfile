#
# Kestrel EDR server image (REST + console + agent gRPC).
# Build from the repository root:
#   docker build -f deploy/Dockerfile -t kestrel-server .
# Skip the console bundle (e.g. while console/ is not ready):
#   docker build -f deploy/Dockerfile --build-arg BUILD_CONSOLE=0 -t kestrel-server .

ARG RUST_IMAGE=rust:1-bookworm
ARG NODE_IMAGE=node:22-bookworm-slim
ARG RUNTIME_IMAGE=debian:bookworm-slim

# ---------------------------------------------------------------- console (optional)
FROM ${NODE_IMAGE} AS console
ARG BUILD_CONSOLE=1
WORKDIR /src/console
COPY console/ ./
RUN mkdir -p dist && \
    if [ "$BUILD_CONSOLE" = "1" ] && [ -f package.json ]; then \
        (if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi) && \
        npm run build ; \
    else \
        echo "console build skipped (BUILD_CONSOLE=$BUILD_CONSOLE)"; \
    fi

# ---------------------------------------------------------------- server
FROM ${RUST_IMAGE} AS server
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY proto proto
# Vendored SigmaHQ Audit pack, embedded into the server (crates/kestrel-server/src/sigmapack.rs).
COPY rules rules
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p kestrel-server && \
    install -m 0755 target/release/kestrel-server /usr/local/bin/kestrel-server

# ---------------------------------------------------------------- runtime
FROM ${RUNTIME_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tini && rm -rf /var/lib/apt/lists/* && \
    useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin kestrel && \
    mkdir -p /app/console /app/agent && chown -R kestrel /app
COPY --from=server /usr/local/bin/kestrel-server /usr/local/bin/kestrel-server
COPY --from=console /src/console/dist/ /app/console/
ENV CONSOLE_DIR=/app/console \
    AGENT_DIR=/app/agent \
    KESTREL_HTTPS_ADDR=0.0.0.0:443 \
    KESTREL_GRPC_ADDR=0.0.0.0:8443 \
    RUST_LOG=info,sqlx=warn
USER kestrel
WORKDIR /app
EXPOSE 443 8443
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
    CMD curl -fsk https://127.0.0.1:443/api/healthz || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/kestrel-server"]
