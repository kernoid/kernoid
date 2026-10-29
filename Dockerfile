# SPDX-License-Identifier: AGPL-3.0-or-later
# One image for every role; the configuration decides what a container does. It carries the Kubernetes operator too.

# The login UI and the web app (web/, MIT): built first, then built into the binary (rust-embed). Install scripts of
# dependencies do not run.
FROM docker.io/library/node:26.11.1-trixie-slim AS web
RUN npm install --global --ignore-scripts --no-audit --no-fund pnpm@12.12.0
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
COPY web/sdk/package.json sdk/
COPY web/login/package.json login/
COPY web/app/package.json app/
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm --filter @kernoid/login --filter @kernoid/app run build

FROM docker.io/library/rust:1.99.1-slim-trixie AS build
WORKDIR /src
# OpenSSL for webauthn-rs (passkeys); the runtime image brings libssl.
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY . .
COPY --from=web /web/login/dist web/login/dist
COPY --from=web /web/app/dist web/app/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin kernoid && cp target/release/kernoid /kernoid
# The Kubernetes operator (operator/, a workspace of its own): the same image runs it.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/operator/target \
    cargo build --release --locked --manifest-path operator/Cargo.toml && cp operator/target/release/kernoid-operator /kernoid-operator

# distroless publishes no version tags; the digest pins the nonroot image of 2026-10-23.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:83b9b50586253821cf63ffcec87d3d94265a093ad30da232039af962dd8f4edf
COPY --from=build /kernoid /usr/local/bin/kernoid
COPY --from=build /kernoid-operator /usr/local/bin/kernoid-operator
EXPOSE 8080 2525
ENTRYPOINT ["/usr/local/bin/kernoid"]
CMD ["serve"]
