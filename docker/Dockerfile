# syntax=docker/dockerfile:1.7
# Gogo Desktop container image (linux/amd64 and linux/arm64).
#
#   docker buildx build -f docker/Dockerfile --platform linux/amd64,linux/arm64 -t gogo-desktop .
#
# Stage 1 builds the web interface, stage 2 cross-compiles the server for the
# target architecture, stage 3 is a minimal distroless runtime (no shell).

FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM rust:1-bookworm AS build
ARG TARGETARCH
ARG BUILDARCH
RUN set -eux; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      case "$TARGETARCH" in \
        arm64) pkgs="gcc-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
        amd64) pkgs="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
      esac; \
      apt-get update && apt-get install -y --no-install-recommends $pkgs && rm -rf /var/lib/apt/lists/*; \
    fi; \
    case "$TARGETARCH" in \
      arm64) rustup target add aarch64-unknown-linux-gnu ;; \
      amd64) rustup target add x86_64-unknown-linux-gnu ;; \
    esac
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY --from=web /src/web/dist ./web/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=gogo-cargo-registry,sharing=locked \
    --mount=type=cache,target=/src/target,id=gogo-target-${TARGETARCH},sharing=locked \
    set -eux; \
    case "$TARGETARCH" in \
      arm64) triple=aarch64-unknown-linux-gnu ;; \
      amd64) triple=x86_64-unknown-linux-gnu ;; \
      *) echo "unsupported architecture $TARGETARCH"; exit 1 ;; \
    esac; \
    cargo build --release --locked -p gogo-server --target "$triple"; \
    cp "target/$triple/release/gogo" /gogo

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="Gogo Desktop" \
      org.opencontainers.image.description="Fast local file search in your browser" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/leoli1110/gogo-desktop"
COPY --from=build /gogo /usr/local/bin/gogo
ENV GOGO_MODE=docker
# /data: database, audit log, certificates (read-write)
# /config: policy.yaml and secrets (mount read-only)
# /libraries/<Name>: shared folders to index (mount read-only)
VOLUME ["/data"]
EXPOSE 4681
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["/usr/local/bin/gogo", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/gogo"]
CMD ["serve"]
